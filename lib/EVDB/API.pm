package EVDB::API;

=head1 NAME

EVDB::API - Perl interface to EVDB public API

=head1 SYNOPSIS

  use EVDB::API;
  
  my $evdb = EVDB::API->new(app_key => $app_key);
  
  $evdb->login(user => 'harry', password => 'H0gwart$') 
    or die "Can't log in: $EVDB::API::errstr";
  
  my $event = $evdb->call('events/get', {id => 'E0-001-000218163-6'})
    or die "Can't retrieve event: $EVDB::API::errstr";
  
  print "Title: $event->{title}\n";

  my $venue = $evdb->call('venues/get', { id => $event->{venue_id} })
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
use Digest::MD5 qw(md5_hex);

=head1 VERSION

0.8 - July 2005

=cut

our $VERSION = 0.8;

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
	my $args = shift || {};
	my $force_array = shift;

	# Construct the method URL.
	my $url = $self->{api_root} . '/rest/' . $method;
	print "Calling ($url)...\n" if $VERBOSE;
	
	# Add the standard arguments to the list.
  $args->{app_key}    = $self->{app_key};
  $args->{user}       = $self->{user};
  $args->{user_key}   = $self->{user_key};
  
	# Construct the POST data by encoding all the arguments.
	my @postParts; 
	foreach my $key (keys %{$args}) 
	{
	  my $name = url_encode($key);
	  my $value = url_encode($args->{$key});
		push(@postParts, "$name=$value");
	}
	my $postData = join('&', @postParts);
	print "POST: ($postData)\n" if $DEBUG;

	# Fetch the data using the POST method.
	my $ua = $self->{user_agent};
	my $request = HTTP::Request->new(POST => $url);
	$request->content_type('application/x-www-form-urlencoded');
	$request->content($postData);
	
	my $response = $ua->request($request);
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
