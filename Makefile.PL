
# $id$

use strict;
use warnings;
use ExtUtils::MakeMaker;

WriteMakefile(
    NAME                => 'Apache2::MultiAuth',
    AUTHOR              => 'Alex Sayle <alexs@alphacomplex.info>',
    VERSION_FROM        => 'lib/Apache2/MultiAuth.pm',
    ABSTRACT_FROM       => 'lib/Apache2/MultiAuth.pm',
    PL_FILES            => {},
    PREREQ_PM => {
        'Test::More' => 0,
        'version'    => 0,
    },
    dist                => { COMPRESS => 'gzip -9f', SUFFIX => 'gz', },
    clean               => { FILES => 'Apache2-MultiAuth-*' },
);
