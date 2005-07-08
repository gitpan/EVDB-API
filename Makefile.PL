use ExtUtils::MakeMaker;

WriteMakefile(
    'NAME'       => 'EVDB::API',
    'VERSION'    => '0.9',
    'PREREQ_PM'	 => 
    {
      'Digest::MD5'       => 0.1,
      'XML::Simple'       => 0.1,
      'LWP::UserAgent'    => 0.1,
    },
);
