<?php

// validates that all security advisories are valid

require __DIR__.'/vendor/autoload.php';

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

$dir = new \RecursiveIteratorIterator(new RecursiveCallbackFilterIterator(new \RecursiveDirectoryIterator(__DIR__), $advisoryFilter));
foreach ($dir as $file) {
    if (!$file->isFile()) {
        continue;
    }

    $path = str_replace(__DIR__.'/', '', $file->getPathname());

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

        if (isset($data['reference']) && 0 !== strpos($data['reference'], 'composer://')) {
            $messages[$path][] = 'Reference must start with "composer://"';
        }

        if (!isset($data['branches'])) {
            continue; // Don't validate branches when not set to avoid notices
        }

        if (!is_array($data['branches'])) {
            $messages[$path][] = '"branches" must be an array.';
            continue;  // Don't validate branches when not set to avoid notices
        }

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
                $hasMax = false;
                foreach ($branch['versions'] as $version) {
                    if ('<' === substr($version, 0, 1)) {
                        $hasMax = true;
                        break;
                    }
                }

                if (!$hasMax) {
                    $messages[$path][] = sprintf('"versions" must have an upper bound for branch "%s".', $name);
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
