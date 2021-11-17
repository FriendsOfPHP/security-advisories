<?php

/**
 * Script for exporting advisories to OSV format.
 *
 * Usage: `php export-osv.php export target_folder`
 *
 * @see https://ossf.github.io/osv-schema/
 */

namespace FriendsOfPhp\SecurityAdvisories;

use Composer\Semver\Semver;
use DirectoryIterator;
use FilesystemIterator;
use SplFileInfo;
use Symfony\Component\Cache\Adapter\FilesystemAdapter;
use Symfony\Component\Console\Application;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputArgument;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Output\OutputInterface;
use Symfony\Component\HttpClient\HttpClient;
use Symfony\Component\Yaml\Yaml;
use Symfony\Contracts\Cache\CacheInterface;
use Symfony\Contracts\HttpClient\Exception\HttpExceptionInterface;

if (!is_file($autoloader = __DIR__ . '/vendor/autoload.php')) {
    echo 'Dependencies are not installed, please run "composer install" first!' . PHP_EOL;
    exit(1);
}

require $autoloader;

final class ExportOsv extends Command
{
    private const OSV_ECOSYSTEM = 'Packagist';
    private const OSV_PACKAGE_URL = 'https://packagist.org/packages/';
    private const OSV_PREFIX = 'PHPSEC';

    protected function configure(): void
    {
        $this
            ->setName('export')
            ->setDescription('Export advisories in OSV format')
            ->addArgument('target',InputArgument::OPTIONAL, 'Target folder', 'packagist');
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        mkdir($targetFolder = $input->getArgument('target'));

        $cache = new FilesystemAdapter();

        $namespaceIterator = new DirectoryIterator(__DIR__);

        // Package namespaces
        foreach ($namespaceIterator as $namespaceInfo) {
            if ($namespaceInfo->isDot() || !$namespaceInfo->isDir() || $namespaceInfo->getFilename() === 'vendor' || strpos($namespaceInfo->getFilename() , '.') === 0) continue;

            $namespace = $namespaceInfo->getFilename();
            $packageIterator = new DirectoryIterator($namespaceInfo->getPathname());

            // Packages inside namespace
            foreach ($packageIterator as $packageInfo) {
                if ($packageIterator->isDot() || !$packageInfo->isDir()) continue;

                $package = [
                    'name' => $namespace . '/' . $packageInfo->getFilename(),
                    'data' => $this->getPackageData($namespace . '/' . $packageInfo->getFilename(), $cache),
                ];

                if (is_null($package['data'])) {
                    $output->writeln('Skipped "' . $package['name'] . '" because it was not found on Packagist');
                    continue;
                }

                $fileSystemIterator = new FilesystemIterator($packageInfo->getPathname());

                $output->write('Converting "' . $package['name'] . '" ...' . str_repeat(' ', 20) . "\r");

                foreach ($fileSystemIterator as $fileInfo) {
                    $osv = $this->convertToOsv($fileInfo, $package);

                    if (is_null($osv)) {
                        $output->writeln('Skipped "' . $package['name'] . '/' . $fileInfo->getFilename() . '" because package is not on Packagist');
                        continue;
                    }

                    if (count($osv['affected']['versions']) === 0) {
                        $output->writeln('Skipped "' . $package['name'] . '/' . $fileInfo->getFilename() . '" because no affected versions are available on Packagist');
                        continue;
                    }

                    $path = $targetFolder . DIRECTORY_SEPARATOR . $osv['id'] . '.json';

                    file_put_contents($path, json_encode($osv, JSON_PRETTY_PRINT));
                }
            }
        }

        $output->writeln('');

        // Command::SUCCESS and Command::FAILURE constants were introduced in Symfony 5.1
        return 0;
    }

    private function convertToOsv(SplFileInfo $fileInfo, array $package): ?array
    {
        $advisory = Yaml::parseFile($fileInfo->getPathname());

        // Advisories with custom repositories are currently not supported
        if (isset($advisory['composer-repository'])) {
            return null;
        }

        return [
            'id' => $advisory['cve'] ?? self::OSV_PREFIX . '-' . $fileInfo->getBasename('.yaml'),
            'modified' => self::getDateFromGitLog($fileInfo),
            'published' => self::getDateFromGitLog($fileInfo, true),
            'aliases' => [],
            'related' => [],
            'summary' => $advisory['title'] ?? '',
            'details' => '',
            'affected' => self::getAffected($advisory, $package),
            'references' => self::getReferences($advisory, $package['name']),
        ];
    }

    private function getPackageData(string $packageName, CacheInterface $cache): ?array
    {
        return $cache->get($packageName, function () use ($packageName) {
            $response = HttpClient::create()->request(
                'GET',
                'https://repo.packagist.org/p2/' . $packageName . '.json'
            );

            try {
                return $response->toArray();
            } catch (HttpExceptionInterface $httpException) {
                return null;
            }
        });
    }

    private static function getAffected(array $advisory, array $package): array
    {
        return [
            'package' => [
                'ecosystem' => self::OSV_ECOSYSTEM,
                'name' => $package['name'],
                'purl' => sprintf('pkg:packagist/%s', $package['name']),
            ],
            'versions' => self::getVersions($advisory['branches'], $package),
        ];
    }

    private static function getDateFromGitLog(SplFileInfo $fileInfo, bool $created = false): string
    {
        $timestamp = shell_exec(sprintf(
            'git log --format="%%at" %s %s %s %s',
            $created ? '' : '--max-count 1',
            $created ? '--reverse' : '',
            escapeshellarg($fileInfo->getPathname()),
            $created ? '| head -1' : ''
        ));

        return date('Y-m-d\TH:i:s\Z', (int) trim($timestamp));
    }

    private static function getVersions(array $branches, array $package): array
    {
        $branchConstraints = array_column($branches, 'versions');

        $versions = array_column($package['data']['packages'][$package['name']], 'version');
        $versionsAffected = [];

        foreach ($branchConstraints as $constraints) {
            foreach (array_reverse($versions) as $version) {
                if (Semver::satisfies($version, implode(' ', $constraints))) {
                    array_push($versionsAffected, $version);
                }
            }
        }

        return $versionsAffected;
    }

    private static function getReferences(array $advisory, string $packageName): array
    {
        return [
            [
                'type' => 'ADVISORY',
                'url' => $advisory['link'],
            ],
            [
                'type' => 'PACKAGE',
                'url' => self::OSV_PACKAGE_URL . $packageName,
            ],
        ];
    }
}

$application = new Application();
$application->add(new ExportOsv());
$application->run();
