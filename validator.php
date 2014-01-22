<?php

// validates that all security advisories are valid

require __DIR__.'/vendor/autoload.php';

use Symfony\Component\Yaml\Parser;
use Symfony\Component\Yaml\Exception\ParseException;

$parser = new Parser();
$messages = array();
$dir = new \RecursiveIteratorIterator(new \RecursiveDirectoryIterator(__DIR__));
foreach ($dir as $file) {
    if (!$file->isFile() || 'yaml' !== $file->getExtension()) {
        continue;
    }

    $path = str_replace(__DIR__.'/', '', $file->getPathname());

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

        if (0 !== strpos($data['reference'], 'composer://')) {
            $messages[$path][] = 'Reference must start with "composer://"';
        }

        if (!is_array($data['branches'])) {
            $messages[$path][] = '"branches" must be an array.';
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

            foreach (array('time', 'versions') as $key) {
                if (!isset($branch[$key])) {
                    $messages[$path][] = sprintf('Key "%s" is required for branch "%s".', $key, $name);
                }
            }

            if (!is_array($branch['versions'])) {
                $messages[$path][] = sprintf('"versions" must be an array for branch "%s".', $name);
            }
        }
    } catch (ParseException $e) {
        $messages[$path][] = sprintf('YAML is not valid (%s).', $e->getMessage());
    }
}

if ($messages) {
    foreach ($messages as $file => $messages) {
        echo "$file\n";
        foreach ($messages as $message) {
            echo "    $message\n";
        }
    }

    exit(1);
}
