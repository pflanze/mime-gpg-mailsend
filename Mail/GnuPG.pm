package Mail::GnuPG;

=head1 NAME

Mail::GnuPG - Process email with GPG.

=head1 SYNOPSIS

  use Mail::GnuPG;
  my $mg = new Mail::GnuPG( key => 'ABCDEFGH' );
  $ret = $mg->mime_sign( $MIMEObj );

=head1 DESCRIPTION

=cut

use 5.006;
use strict;
use warnings;

our $VERSION = '0.15';
our $DEBUG = 0;

use MIME::Entity;
use Mail::Address;
use IO::Select;
use Errno qw(EPIPE);
use Carp 'shortmess';

our $show_type_warnings=1;
our $seen_warnings={};
sub Warn_check_class ( $ $ ) {
    return unless $show_type_warnings;
    my ($obj, $class)=@_;
    ref $obj and $obj->isa($class)
      or do {
	  my $msg=shortmess ("");
	  if ($$seen_warnings{$msg}) {
	      #ignore
	  } else {
	      $$seen_warnings{$msg}=1;
	      warn __PACKAGE__." warning (shown only once per location): expected an object of class $class, but got: '$obj'".$msg;
	  }
      };
}


=head2 new

  Create a new Mail::GnuPG instance.

 Arguments:
   Parameter key/value pairs:

   key    => gpg key id
   keydir => gpg configuration/key directory
   passphrase => primary key password

   # FIXME: we need more things here, maybe primary key id.


=cut

sub new {
  my $proto = shift;
  my $class = ref($proto) || $proto;
  my $self  = {
	       key	    => undef,
	       keydir	    => undef,
	       passphrase   => "",
	       gpg_path	    => "gpg",
	       @_
	      };
  $self->{last_message} = [];
  $self->{plaintext} = [];
  bless ($self, $class);
  return $self;
}



# Should this go elsewhere?  The Key handling stuff doesn't seem to
# make sense in a Mail:: module.  
my %key_cache;
my $key_cache_age = 0;
my $key_cache_expire = 60*60*30; # 30 minutes

sub _rebuild_key_cache {
  my $self = shift;
  local $_;
  %key_cache = ();
  # sometimes the best tool for the job... is not perl
  open(my $fh, "$self->{gpg_path} --list-public-keys --with-colons | cut -d: -f10|")
    or die $!;
  while(<$fh>) {
    next unless $_;
    # M::A may not parse the gpg stuff properly.  Cross fingers
    my ($a) = Mail::Address->parse($_); # list context, please
    $key_cache{$a->address}=1 if ref $a;
  }
}

=head2 has_public_key

Does the keyring have a public key for the specified email address? 

 FIXME: document better.  talk about caching.  maybe put a better
 interface in.

=cut


sub has_public_key {
  my ($self,$address) = @_;

  # cache aging is disabled until someone has enough time to test this
  if (0) {
    $self->_rebuild_key_cache() unless ($key_cache_age);

    if ( $key_cache_age && ( time() - $key_cache_expire > $key_cache_age )) {
      $self->_rebuild_key_cache();
    }
  }

  $self->_rebuild_key_cache();

  return 1 if exists $key_cache{$address};
  return 0;

}

=head2 mime_sign

  sign an email message

 Input:
   MIME::Entity containing email message to sign

 Output:
  Exit code of gpg.  (0 on success)

  $self->{last_message} => any errors from gpg

  The provided $entity will be signed.  (i.e. it _will_ be modified.)

=cut


sub mime_sign {
  my ($self,$entity) = @_;
  Warn_check_class ($entity,"MIME::Entity");

  $entity->make_multipart;
  my $workingentity = $entity;
  if ($entity->parts > 1) {
    $workingentity = MIME::Entity->build(Type => $entity->head->mime_attr("Content-Type"));
    $workingentity->add_part($_) for ($entity->parts);
    $entity->parts([]);
    $entity->add_part($workingentity);
  }

  my $gnupg = GnuPG::Interface->new();
  $self->_set_options( $gnupg );
  my ( $input, $output, $error, $passphrase_fh, $status_fh )
    = ( new IO::Handle, new IO::Handle,new IO::Handle,
	new IO::Handle,new IO::Handle,);
  my $handles = GnuPG::Handles->new( stdin      => $input,
				     stdout     => $output,
				     stderr     => $error,
				     passphrase => $passphrase_fh,
				     status     => $status_fh,
				   );
  my $pid = $gnupg->detach_sign( handles => $handles );
  die "NO PASSPHRASE" unless defined $passphrase_fh;

  # this passes in the plaintext
  my $plaintext;
  if ($workingentity eq $entity) {
    $plaintext = $entity->parts(0)->as_string;
  } else {
    $plaintext = $workingentity->as_string;
  }

  # according to RFC3156 all line endings MUST be CR/LF
  $plaintext =~ s/\x0A/\x0D\x0A/g;
  $plaintext =~ s/\x0D+/\x0D/g;

  # DEBUG:
#  print "SIGNING THIS STRING ----->\n";
#  $plaintext =~ s/\n/-\n/gs;
#  warn("SIGNING:\n$plaintext<<<");
#  warn($entity->as_string);
#  print STDERR $plaintext;
#  print "<----\n";
  my $read = _communicate([$output, $error, $status_fh],
                        [$input, $passphrase_fh],
                        { $input => $plaintext,
                          $passphrase_fh => $self->{passphrase}}
             );

  my @signature  = split(/^/m, $read->{$output});
  my @error_output = split(/^/m, $read->{$error});
  my @status_info  = split(/^/m, $read->{$status_fh});

  waitpid $pid, 0;
  my $return = $?;
   $return = 0 if $return == -1;

  my $exit_value  = $return >> 8;


  $self->{last_message} = \@error_output;

  $entity->attach( Type => "application/pgp-signature",
		   Disposition => "inline",
		   Data => [@signature],
		   Encoding => "7bit");

  $entity->head->mime_attr("Content-Type","multipart/signed");
  $entity->head->mime_attr("Content-Type.protocol","application/pgp-signature");
#  $entity->head->mime_attr("Content-Type.micalg","pgp-md5");
# Richard Hirner notes that Thunderbird/Enigmail really wants a micalg
# of pgp-sha1 (which will be GPG version dependent.. older versions
# used md5.  For now, until we can detect which type was used, the end
# user should read the source code, notice this comment, and insert
# the appropriate value themselves.

  return $exit_value;
}



=head2 is_signed

  best guess as to whether a message is signed or not (by looking at
  the mime type and message content)

 Input:
   MIME::Entity containing email message to test

 Output:
  True or False value

=head2 is_encrypted

  best guess as to whether a message is signed or not (by looking at
  the mime type and message content)

 Input:
   MIME::Entity containing email message to test

 Output:
  True or False value

=cut

sub is_signed {
  my ($self,$entity) = @_;
  Warn_check_class ($entity,"MIME::Entity");
  return 1
    if (($entity->effective_type =~ m!multipart/signed!)
	||
	($entity->as_string =~ m!^-----BEGIN PGP SIGNED MESSAGE-----!m));
  return 0;
}

sub is_encrypted {
  my ($self,$entity) = @_;
  Warn_check_class ($entity,"MIME::Entity");
  return 1
    if (($entity->effective_type =~ m!multipart/encrypted!)
	||
	($entity->as_string =~ m!^-----BEGIN PGP MESSAGE-----!m));
  return 0;
}

# interleave reads and writes
# input parameters: 
#  $rhandles - array ref with a list of file handles for reading
#  $whandles - array ref with a list of file handles for writing
#  $wbuf_of  - hash ref indexed by the stringified handles
#              containing the data to write
# return value:
#  $rbuf_of  - hash ref indexed by the stringified handles
#              containing the data that has been read
#
# read and write errors due to EPIPE (gpg exit) are skipped silently on the
# assumption that gpg will explain the problem on the error handle
#
# other errors cause a non-fatal warning, processing continues on the rest
# of the file handles
#
# NOTE: all the handles get closed inside this function

sub _communicate {
    my $blocksize = 2048;
    my ($rhandles, $whandles, $wbuf_of) = @_;
    my $rbuf_of = {};

    # the current write offsets, again indexed by the stringified handle
    my $woffset_of;

    my $reader = IO::Select->new;
    for (@$rhandles) {
        $reader->add($_);
        $rbuf_of->{$_} = '';
    }

    my $writer = IO::Select->new;
    for (@$whandles) {
        die("no data supplied for handle " . fileno($_)) if !exists $wbuf_of->{$_};
        if ($wbuf_of->{$_}) {
            $writer->add($_);
        } else { # nothing to write
            close $_;
        }
    }

    # we'll handle EPIPE explicitly below
    local $SIG{PIPE} = 'IGNORE';

    while ($reader->handles || $writer->handles) {
        my @ready = IO::Select->select($reader, $writer, undef, undef);
        if (!@ready) {
            die("error doing select: $!");
        }
        my ($rready, $wready, $eready) = @ready;
        if (@$eready) {
            die("select returned an unexpected exception handle, this shouldn't happen");
        }
        for my $rhandle (@$rready) {
            my $n = fileno($rhandle);
            my $count = sysread($rhandle, $rbuf_of->{$rhandle},
                                $blocksize, length($rbuf_of->{$rhandle}));
            warn("read $count bytes from handle $n") if $DEBUG;
            if (!defined $count) { # read error
                if ($!{EPIPE}) {
                    warn("read failure (gpg exited?) from handle $n: $!")
                        if $DEBUG;
                } else {
                    warn("read failure from handle $n: $!");
                }
                $reader->remove($rhandle);
                close $rhandle;
                next;
            }
            if ($count == 0) { # EOF
                warn("read done from handle $n") if $DEBUG;
                $reader->remove($rhandle);
                close $rhandle;
                next;
            }
        }
        for my $whandle (@$wready) {
            my $n = fileno($whandle);
            $woffset_of->{$whandle} = 0 if !exists $woffset_of->{$whandle};
            my $count = syswrite($whandle, $wbuf_of->{$whandle},
                                 $blocksize, $woffset_of->{$whandle});
            if (!defined $count) {
                if ($!{EPIPE}) { # write error
                    warn("write failure (gpg exited?) from handle $n: $!")
                        if $DEBUG;
                } else {
                    warn("write failure from handle $n: $!");
                }
                $writer->remove($whandle);
                close $whandle;
                next;
            }
            warn("wrote $count bytes to handle $n") if $DEBUG;
            $woffset_of->{$whandle} += $count;
            if ($woffset_of->{$whandle} >= length($wbuf_of->{$whandle})) {
                warn("write done to handle $n") if $DEBUG;
                $writer->remove($whandle);
                close $whandle;
                next;
            }
        }
    }
    return $rbuf_of;
}

# FIXME: there's no reason why is_signed and is_encrypted couldn't be
# static (class) methods, so maybe we should support that.

# FIXME: will we properly deal with signed+encrypted stuff?  probably not.

# Autoload methods go after =cut, and are processed by the autosplit program.

1;
__END__

=head1 LICENSE

Copyright 2003 Best Practical Solutions, LLC

This program is free software; you can redistribute it and/or modify
it under the terms of either:

    a) the GNU General Public License as published by the Free
    Software Foundation; version 2
    http://www.opensource.org/licenses/gpl-license.php

    b) the "Artistic License"
    http://www.opensource.org/licenses/artistic-license.php

This program is distributed in the hope that it will be useful, but
WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See either the
GNU General Public License or the Artistic License for more details.

=head1 AUTHOR

Robert Spier

=head1 BUGS/ISSUES/PATCHES

Please send all bugs/issues/patches to
    bug-Mail-GnuPG@rt.cpan.org

=head1 SEE ALSO

L<perl>.

MIME::Entity

=cut
