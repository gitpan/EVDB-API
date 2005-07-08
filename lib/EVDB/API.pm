package EVDB::API;

=head1 NAME

EVDB::API - Perl interface to EVDB public API

=head1 SYNOPSIS

  use EVDB::API;
  
  my $evdb = EVDB::API->new(app_key => $app_key);
  
  $evdb->login(user => 'harry', password => 'H0gwart$') 
    or die "Can't log in: $EVDB::API::errstr";
  
  # call() accepts either an array ref or a hash ref.
  my $event = $evdb->call('events/get', {id => 'E0-001-000218163-6'})
    or die "Can't retrieve event: $EVDB::API::errstr";
  
  print "Title: $event->{title}\n";

  my $venue = $evdb->call('venues/get', [id => $event->{venue_id}])
    or die "Can't retrieve venue: $EVDB::API::errstr";
  
  print "Venue: $venue->{name}\n";


=head1 DESCRIPTION

The EVDB API allows you to build tools and applications that interact with EVDB, the Events & Venues Database.  This module provides a Perl interface to that  API, including the digest-based authentication infrastructure.  

See http://api.evdb.com/ for details.

=head1 AUTHOR

Copyright 2005 EVDB, Inc. All rights reserved.

=cut

require 5.6.0;

use strict;
use warnings;
no warnings qw(uninitialized);

use XML::Simple;
use LWP::UserAgent;
use HTTP::Request::Common;
use Digest::MD5 qw(md5_hex);

=head1 VERSION

0.9 - July 2005

=cut

our $VERSION = 0.9;

our $VERBOSE = 0;
our $DEBUG = 0;

our $default_api_server = 'http://api.evdb.com';

our $errcode;
our $errstr;

=head1 CLASS METHODS

=item C(new)
  
  $evdb = EVDB::API->new(app_key => $app_key);

Creates a new API object. Requires a valid app_key as provided by EVDB.

=cut

sub new
{
  my $thing = shift;
  my $class = ref($thing) || $thing;
  
  my %params = @_;
  my $self = 
  {
    'app_key'     => $params{app_key} || $params{app_token},
    'debug'       => $params{debug},
    'verbose'     => $params{verbose},
    'user_key'    => '',
    'api_root'    => $params{api_root} || $default_api_server,
  };
  
  $DEBUG   ||= $params{debug};
  $VERBOSE ||= $params{verbose};
  
  print "Creating object in class ($class)...\n" if $VERBOSE;
  
  bless $self, $class;
  
  # Create an LWP user agent for later use.
  $self->{user_agent} = LWP::UserAgent->new(
		agent => "EVDB_API_Perl_Wrapper/$VERSION",
	);
  
  return $self;
}

=head1 OBJECT METHODS

=item C<login>

  $evdb->login(user => $username, password => $password);
  $evdb->login(user => $username, password_md5 => $password_md5);

Retrieves an authentication token from the EVDB API server.

=cut

sub login 
{
  my $self = shift;
  
  my %args = @_;
  
  $self->{user} = $args{user};
  
  # Call login to receive a nonce.
  # (The nonce is stored in an error structure.)
  $self->call('users/login');
  my $nonce = $self->{response_data}{nonce} or return;
  
  # Generate the digested password response.
  my $password_md5 = $args{password_md5} || md5_hex($args{password});
  my $response = md5_hex( $nonce . ":" . $password_md5 );
  
  # Send back the nonce and response.
  my $params = 
  {
    nonce => $nonce,
    response => $response,
  };
  
  my $r = $self->call('users/login', $params) or return;
  
  # Store the provided user_key.
  $self->{user_key} = $r->{user_key} || $r->{auth_token};
  
  return 1;
}

=item C<call>

  $xml_ref = $evdb->call($method, \%arguments, [$force_array]);

Calls the specified method with the given arguments and any previous authentication information (including app_key).  Returns a data structure processed through XML::Simple.

=cut

sub call 
{
  my $self = shift;
  
	my $method = shift;
	my $args = shift || [];
	my $force_array = shift;

	# Construct the method URL.
	my $url = $self->{api_root} . '/rest/' . $method;
	print "Calling ($url)...\n" if $VERBOSE;
	
	# Pre-process the arguments into a hash (for searching) and an array ref
	# (to pass on to HTTP::Request::Common).
	my $arg_present = {};
	if (ref($args) eq 'ARRAY')
	{
	  # Create a hash of the array values (assumes [foo => 'bar', baz => 1]).
	  my %arg_present = @{$args};
	  $arg_present = \%arg_present;
	}
	elsif (ref($args) eq 'HASH')
	{
	  # Migrate the provided hash to an array ref.
	  $arg_present = $args;
	  my @args = %{$args};
	  $args = \@args;
	}
	else
	{
		$errcode = 'Missing parameter';
		$errstr  = 'Missing parameters: The second argument to call() should be an array or hash reference.';
		return undef;
	}
	
	# Add the standard arguments to the list.
	foreach my $k ('app_key', 'user', 'user_key')
	{
	  if ($self->{$k} and !$arg_present->{$k})
	  {
      push @{$args}, $k, $self->{$k};
    }
  }
  
  # If one of the arguments is a file, set up the Common-friendly 
  # file indicator field and set the content-type.
  my $content_type = '';
  foreach my $this_field (keys %{$arg_present})
  {
    # Any argument with a name that ends in "_file" is a file.
    if ($this_field =~ /_file$/)
    {
      $content_type = 'form-data';
      next if ref($arg_present->{$this_field}) eq 'ARRAY'; 
      my $file = 
      [
        $arg_present->{$this_field},
      ];
      
      # Replace the original argument with the file indicator.
      $arg_present->{$this_field} = $file;
      my $last_arg = scalar(@{$args}) - 1;
      ARG: for my $i (0..$last_arg)
      {
        if ($args->[$i] eq $this_field)
        {
          # If this is the right arg, replace the item after it.
          splice(@{$args}, $i + 1, 1, $file);
          last ARG;
        }
      }
    }
  }
  
	# Fetch the data using the POST method.
	my $ua = $self->{user_agent};
	
	my $response = $ua->request(POST $url, 
	  'Content-type' => $content_type, 
	  'Content' => $args,
	);
	unless ($response->is_success) 
	{
		$errcode = $response->code;
		$errstr  = $response->code . ': ' . $response->message;
		return undef;
	}
	
	my $xml = $self->{response_xml} = $response->content();

	# Now parse the XML response into a Perl data structure.
	my $xs = new XML::Simple(
		ForceArray => $force_array,
		KeyAttr => '',
		SuppressEmpty => '',
	);
	my $data = $self->{response_data} = $xs->XMLin($xml);
	
	# Check for errors.
	if ($data->{string})
	{
	  $errcode = $data->{string};
	  $errstr  = $data->{string} . ": " .$data->{description};
	  print "\n", $xml, "\n" if $DEBUG;
	  return undef;
	}

	return $data;
}

# Copied shamelessly from CGI::Minimal.
sub url_encode 
{
	my $s = shift;
	return '' unless defined($s);
	
	# Filter out any URL-unfriendly characters.
	$s =~ s/([^-_.a-zA-Z0-9])/"\%".unpack("H",$1).unpack("h",$1)/egs;
	
	return $s;
}

1;

__END__


=cut
