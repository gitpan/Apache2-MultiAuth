package Apache2::MultiAuth;

# $id$

use warnings FATAL => 'all',  NONFATAL => 'redefine' ;
use strict;
use Carp;

use version; our $VERSION = qv('0.0.2');


use Apache2::Const -compile => qw(OR_ALL ITERATE OK AUTH_REQUIRED);


use Apache2::Module     ();
use Apache2::Access     ();
use Apache2::ServerRec  ();
use Apache2::Directive  ();

use Apache2::RequestRec ();
use Apache2::ServerUtil ();

use APR::Table ();
use APR::Pool  ();


my @directives = (
    {
     name         => 'AuthModule',
     func         => __PACKAGE__ . '::AuthModule',
     req_override => Apache2::Const::OR_ALL,
     args_how     => Apache2::Const::ITERATE,
     errmsg       => 'AuthModule module1 [module2 ... [moduleN]]',
    },
    {
     name         => 'MyOtherParameter',
    },
);


Apache2::Module::add(__PACKAGE__, \@directives);


sub AuthModule {
    my ($self, $parms, @module) = @_;
    
    my $auth_modules = $self->{AuthModules} ||= [];
    push @{$auth_modules}, @module;
    
    # validate that the arguments are strings
    for (@module) {
        unless ( m{\A [\w:]+ \z}xms ) {
            my $directive = $parms->directive;
            die sprintf "Error: AuthModule at %s:%d expects " .
                "string arguments: ('$_' is not a string)\n",
                $directive->filename, $directive->line_num;
        }
    }
}


sub DIR_MERGE {
    my ($parent, $current) = @_;
    my %uniq;
    my @auth_modules = grep { ++$uniq{$_} == 1 }
                        (@{$parent->{AuthModules}},
                         @{$current->{AuthModules}});
                         
    my $new = { AuthModules => \@auth_modules };
    return bless $new, ref $parent;
}


sub handler {
    my $r = shift;

    my( $status, $sent_pw ) = $r->get_basic_auth_pw;
    return $status unless $status == Apache2::Const::OK;

    
    
    #
    # Retrieve the list of auth modules from the module configuration
    #
    my $s = $r->server();
    
    my $PRINT_AUTH_MODULES = $s->dir_config('multiauth_print_modules') || 0 ;
    
    
    my @auth_modules;
    if (my $cfg =  Apache2::Module::get_config('Apache2::MultiAuth',
                                                $s, $r->per_dir_config ) ) {
      
        @auth_modules = @{$cfg->{AuthModules}} if $cfg->{AuthModules};
        
        if ($PRINT_AUTH_MODULES) {
            local $" = "', '";
            $r->log->warn("Registered AuthModules: '@auth_modules'");
        }
    }


    #
      # Iterate through them, short-circuiting when one returns OK
      #
      for my $module (@auth_modules) {

        if ( not eval "require $module"  ){
              $r->log_error( qq(WARN: Failed to import module : $module :$@ ) );
              next;
          }


          my $handler = $module->can('handler') or next;
          if ($handler->($r) == Apache2::Const::OK) {
              $r->log->warn("$module returned OK");
              
              # create table and then set the values .... 
              # why notes can't handle a simple hash table and then do all
              # the conversion ... only the auther(s) know.
              my $table = APR::Table::make( APR::Pool->new, 1);
              $table->set("AuthenticatedBy",$module);
              $r->notes($table);
              return  Apache2::Const::OK
          }

          $r->log_reason("$module did not return OK");
      }

      $r->note_basic_auth_failure;
      return  Apache2::Const::AUTH_REQUIRED;

}


1;




1; # Magic true value required at end of module
__END__

=head1 NAME

Apache2::MultiAuth - Use a number of authentication modules at runtime


=head1 VERSION

This document describes Apache2::MultiAuth version 0.0.1


=head1 SYNOPSIS

    use Apache2::MultiAuth;

Insert the something like the following into you apache configuration file(s)


    PerlLoadModule Apache2::MultiAuth
    
    <Location /test>
       AuthName Test 
       AuthType Basic
       
       # PerlSetVars for various Auth* modules
       # These here are example values for Apache2::AuthenSmb
       PerlSetVar myPDC SAMBA
       PerlSetVar myDOMAIN ARBEITSGRUPPE
       
       # These here are example values for Apache2::AuthNetLDAP
       PerlSetVar BindDN "uid=user1,ou=people,o=acme.com" #optional
       PerlSetVar BindPWD "password" #optional
       
       
       
       # Define order and class of Auth modules to try
       AuthModule Apache2::AuthNetLDAP  Apache::AuthenNIS Apache2::AuthenSmb
       
       PerlAuthenHandler Apache2::MultiAuth
       require valid-user
     </Location>

The new directive that that Apache2::MultiAuth Provides is AuthModule with 
the syntax 

    AuthModule <module 1> <module 2> ..... <module 3>

Apache2::MultiAuth does not provide any mechanism to controll the 
configuration of the auth modules that is will be consulting. Please 
look the individual modules documentation for specific configuration.


=head1 DESCRIPTION

Apache2::MultiAuth allows you to specify multiple authentication
modules, to be tried in order.  If any module in the list returns OK,
then the user is considered authenticated; if none return OK, then the
MultiAuth module returns AUTH_REQUIRED and the user is reprompted for 
credentials. This, depending on the browser, results in a 401 authorization
required message.

This is useful for cases where, for example, you have several
authentication schemes:  for example, NIS, SMB, and htpasswd, and some
of your users are only registered in some of the auth databases.
Using Apache::MultiAuth, they can be queried in order until the right
one is found.

In the event that one of these modules returns OK, a note named
"AuthenticatedBy" will be set, which contains the name of the module
that returned OK, like so:

    $my $table = APR::Table::make( APR::Pool->new, 1);
    $table->set("AuthenticatedBy",$module);
    $r->notes($table);

This can be retrieved by any handler that runs after the authentication
phase, and can be very useful in logging:

    CustomLog "%h %l %u %t \"%r\" %>s %b %{AuthenticatedBy}n" common_auth

The last field in the common_auth log format will be the name of the module 
that handled the authentication.

=head1 INTERFACE 

Apache2::MultiAUth is does not have a pgrammable interface, although placing 

    PerlSetVar multiauth_print_modules 1

in your apache configuration file will force Apache2::MultiAuth to report 
the Authenication modules that is it using to the apache log at the log 
level of warn. 

=head1 DIAGNOSTICS

=for author to fill in:
    List every single error and warning message that the module can
    generate (even the ones that will "never happen"), with a full
    explanation of each problem, one or more likely causes, and any
    suggested remedies.

=over

=item C<< [error] access to %s failed for $s, reason: %s did not return OK >>

Strings : URI, Client IP address, Authenticating Module 

When an authenticating module can not authenticate the user, the above 
message pattern is printed to apache's log file at the log level of error()

=item C<< [error] WARN: Failed to import module : %s : $@ >>

Strings : Authenticaing Module , error message from rquire 

Apache2::MultiAuth uses reqire to import the module, if the module 
can't not be loaded for one reason or another, that matter is reported
to the apache log file at the log level of warn(), this doesn't prevent 
other modules to continue authenticating.

=back


=head1 CONFIGURATION AND ENVIRONMENT


Apache2::MultiAuth requires no configuration files or environment variables.


=head1 DEPENDENCIES

Apache2::MutliAuth requires mod_perl2. 



=head1 INCOMPATIBILITIES

Apache2::MutliAuth is not compatible with  mod_perl version 1 

=head1 BUGS AND LIMITATIONS

No bugs have been reported.

Please report any bugs or feature requests to
C<bug-apache2-multiauth@rt.cpan.org>, or through the web interface at
L<http://rt.cpan.org>.


=head1 AUTHOR

Alex Sayle  C<< <alexs@allphacomplex.info> >>


=head1 LICENCE AND COPYRIGHT

Copyright (c) 2007, Alex Sayle C<< <alexs@allphacomplex.info> >>. All rights reserved.

This module is free software; you can redistribute it and/or
modify it under the same terms as Perl itself. See L<perlartistic>.


=head1 DISCLAIMER OF WARRANTY

BECAUSE THIS SOFTWARE IS LICENSED FREE OF CHARGE, THERE IS NO WARRANTY
FOR THE SOFTWARE, TO THE EXTENT PERMITTED BY APPLICABLE LAW. EXCEPT WHEN
OTHERWISE STATED IN WRITING THE COPYRIGHT HOLDERS AND/OR OTHER PARTIES
PROVIDE THE SOFTWARE "AS IS" WITHOUT WARRANTY OF ANY KIND, EITHER
EXPRESSED OR IMPLIED, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE. THE
ENTIRE RISK AS TO THE QUALITY AND PERFORMANCE OF THE SOFTWARE IS WITH
YOU. SHOULD THE SOFTWARE PROVE DEFECTIVE, YOU ASSUME THE COST OF ALL
NECESSARY SERVICING, REPAIR, OR CORRECTION.

IN NO EVENT UNLESS REQUIRED BY APPLICABLE LAW OR AGREED TO IN WRITING
WILL ANY COPYRIGHT HOLDER, OR ANY OTHER PARTY WHO MAY MODIFY AND/OR
REDISTRIBUTE THE SOFTWARE AS PERMITTED BY THE ABOVE LICENCE, BE
LIABLE TO YOU FOR DAMAGES, INCLUDING ANY GENERAL, SPECIAL, INCIDENTAL,
OR CONSEQUENTIAL DAMAGES ARISING OUT OF THE USE OR INABILITY TO USE
THE SOFTWARE (INCLUDING BUT NOT LIMITED TO LOSS OF DATA OR DATA BEING
RENDERED INACCURATE OR LOSSES SUSTAINED BY YOU OR THIRD PARTIES OR A
FAILURE OF THE SOFTWARE TO OPERATE WITH ANY OTHER SOFTWARE), EVEN IF
SUCH HOLDER OR OTHER PARTY HAS BEEN ADVISED OF THE POSSIBILITY OF
SUCH DAMAGES.
