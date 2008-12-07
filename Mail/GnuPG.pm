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



=head2 mime_sign

  sign an email message

 Input:
   MIME::Entity containing email message to sign

 Output:
  Exit code of gpg.  (0 on success)

  $self->{last_message} => any errors from gpg

  The provided $entity will be signed.  (i.e. it _will_ be modified.)

=cut



use Chj::xtmpfile ();
use Chj::IO::Command;
use Chj::xperlfunc ();

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

  my $gpgoutputfile= Chj::xtmpfile::xtmpfile;
  my $gpg_out= Chj::IO::Command->new_receiver
    (sub {
	 $gpgoutputfile->xdup2(1);
	 Chj::xperlfunc::xexec
	     ("gpg",
	      "--detach-sign",
	      "--armor", # required
	      ($$self{key} ? ("--local-user",$$self{key}) : ()),
	     );
     });

  my $plaintext = (($workingentity eq $entity) ?
		   $entity->parts(0)->as_string
		   :
		   $workingentity->as_string);

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

  $gpg_out->xprint ($plaintext);
  my $return= $gpg_out->xfinish;

  $gpgoutputfile ->xrewind; # required.
  my @signature  = <$gpgoutputfile>;
  $gpgoutputfile->xclose;

  #$self->{last_message} = \@error_output;   we don't have this anymore

  $entity->attach( Type => "application/pgp-signature",
		   Disposition => "inline",
		   Data => \@signature,
		   Encoding => "7bit");

  $entity->head->mime_attr("Content-Type","multipart/signed");
  $entity->head->mime_attr("Content-Type.micalg","pgp-sha1");
  $entity->head->mime_attr("Content-Type.protocol","application/pgp-signature");
#  $entity->head->mime_attr("Content-Type.micalg","pgp-md5");
# Richard Hirner notes that Thunderbird/Enigmail really wants a micalg
# of pgp-sha1 (which will be GPG version dependent.. older versions
# used md5.  For now, until we can detect which type was used, the end
# user should read the source code, notice this comment, and insert
# the appropriate value themselves.

  return $return;
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
