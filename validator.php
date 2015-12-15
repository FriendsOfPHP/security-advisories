<?php

// validates that all security advisories are valid

if (!is_file($autoloader = __DIR__.'/vendor/autoload.php')) {
    echo "Dependencies are not installed, please run 'composer install' first!\n";
    exit(1);
}
require $autoloader;

use Symfony\Component\Yaml\Parser;
use Symfony\Component\Yaml\Exception\ParseException;

$parser = new Parser();
$messages = array();

$advisoryFilter = function (SplFileInfo $file) {
    if ($file->isFile() && __DIR__ === $file->getPath()) {
        return false; // We want to skip root files
    }

    if ($file->isDir()) {
        if (__DIR__.DIRECTORY_SEPARATOR.'vendor' === $file->getPathname()) {
            return false; // We want to skip the vendor dir
        }

        $dirName = $file->getFilename();
        if ('.' === $dirName[0]) {
            return false; // Exclude hidden folders (.git and IDE folders at the root)
        }
    }

    return true; // any other file gets checks and any other folder gets iterated
};

$isAcceptableVersionConstraint = function ($versionString) {
    return (bool) preg_match('/^(\\<|\\>)(=){0,1}(([1-9]\d*)|0)(\.(([1-9]\d*)|0))*(-(alpha|beta|rc)[1-9]\d*){0,1}$/', $versionString);
};

/* @var $dir \SplFileInfo[] */
$dir = new \RecursiveIteratorIterator(new RecursiveCallbackFilterIterator(new \RecursiveDirectoryIterator(__DIR__), $advisoryFilter));
foreach ($dir as $file) {
    if (!$file->isFile()) {
        continue;
    }

    $path = str_replace(__DIR__.DIRECTORY_SEPARATOR, '', $file->getPathname());

    if ('yaml' !== $file->getExtension()) {
        $messages[$path][] = 'The file extension should be ".yaml".';
        continue;
    }

    try {
        $data = $parser->parse(file_get_contents($file));

        // validate first level keys
        if ($keys = array_diff(array_keys($data), array('reference', 'branches', 'title', 'link', 'cve'))) {
            foreach ($keys as $key) {
                $messages[$path][] = sprintf('Key "%s" is not supported.', $key);
            }
        }

        // required keys
        foreach (array('reference', 'title', 'link', 'branches') as $key) {
            if (!isset($data[$key])) {
                $messages[$path][] = sprintf('Key "%s" is required.', $key);
            }
        }

        if (isset($data['reference'])) {
            if (0 !== strpos($data['reference'], 'composer://')) {
                $messages[$path][] = 'Reference must start with "composer://"';
            } else {
                $composerPackage = substr($data['reference'], 11);

                if (str_replace(DIRECTORY_SEPARATOR, '/', dirname($path)) !== $composerPackage) {
                    $messages[$path][] = 'Reference composer package must match the folder name';
                }

                $packagistUrl = sprintf('https://packagist.org/packages/%s.json', $composerPackage);

                if(404 == explode(' ', get_headers($packagistUrl)[0], 3)[1]) {
                    $messages[$path][] = sprintf('Invalid composer package');
                }
            }
        }

        if (!isset($data['branches'])) {
            continue; // Don't validate branches when not set to avoid notices
        }

        if (!is_array($data['branches'])) {
            $messages[$path][] = '"branches" must be an array.';
            continue;  // Don't validate branches when not set to avoid notices
        }

        $upperBoundWithoutLowerBound = null;

        foreach ($data['branches'] as $name => $branch) {
            if (!preg_match('/^([\d\.\-]+(\.x)?(\-dev)?|master)$/', $name)) {
                $messages[$path][] = sprintf('Invalid branch name "%s".', $name);
            }

            if ($keys = array_diff(array_keys($branch), array('time', 'versions'))) {
                foreach ($keys as $key) {
                    $messages[$path][] = sprintf('Key "%s" is not supported for branch "%s".', $key, $name);
                }
            }

            if (!isset($branch['time'])) {
                $messages[$path][] = sprintf('Key "time" is required for branch "%s".', $name);
            }

            if (!isset($branch['versions'])) {
                $messages[$path][] = sprintf('Key "versions" is required for branch "%s".', $name);
            } elseif (!is_array($branch['versions'])) {
                $messages[$path][] = sprintf('"versions" must be an array for branch "%s".', $name);
            } else {
                $upperBound = null;
                $hasMin = false;
                foreach ($branch['versions'] as $version) {
                    if (! $isAcceptableVersionConstraint($version)) {
                        $messages[$path][] = sprintf('Version constraint "%s" is not in an acceptable format.', $version);
                    }

                    if ('<' === substr($version, 0, 1)) {
                        $upperBound = $version;
                        continue;
                    }
                    if ('>' === substr($version, 0, 1)) {
                        $hasMin = true;
                    }
                }

                if (null === $upperBound) {
                    $messages[$path][] = sprintf('"versions" must have an upper bound for branch "%s".', $name);
                }

                if (!$hasMin && null === $upperBoundWithoutLowerBound) {
                    $upperBoundWithoutLowerBound = $upperBound;
                }

                // Branches can omit the lower bound only if their upper bound is the same than for other branches without lower bound.
                if (!$hasMin && $upperBoundWithoutLowerBound !== $upperBound) {
                    $messages[$path][] = sprintf('"versions" must have a lower bound for branch "%s" to avoid overlapping lower branches.', $name);
                }
            }
        }
    } catch (ParseException $e) {
        $messages[$path][] = sprintf('YAML is not valid (%s).', $e->getMessage());
    }
}

if ($messages) {
    foreach ($messages as $file => $fileMessages) {
        echo "$file\n";
        foreach ($fileMessages as $message) {
            echo "    $message\n";
        }
    }

    exit(1);
}
