PHP Security Advisories Database
================================

The PHP Security Advisories Database references known security
vulnerabilities in various PHP projects and libraries. This database **must
not** serve as the primary source of information for security issues, it is
not authoritative for any referenced software, but it allows to centralize
information for convenience and easy consumption.

License
-------

The PHP security advisories database is free and unencumbered software released
into the public domain.

Checking for Vulnerabilities
----------------------------

There are several possibilities to check for vulnerabilities in your
applications beside manual checks:

 * Upload your `composer.lock` file on https://security.symfony.com/;

 * Use the [CLI tool][1]:

        php checker security:check /path/to/composer.lock

 * Use the web service:

        curl -H "Accept: text/plain" https://security.symfony.com/check_lock -F lock=@/path/to/composer.lock

   It will return all vulnerabilities detected in your dependencies in plain
   text. You can also retrieve the information in the JSON format:

        curl -H "Accept: application/json" https://security.symfony.com/check_lock -F lock=@/path/to/composer.lock

It is therefore convenient to include the call to the Symfony Web Service in any build plans or existing Continuous Integration workflow, so that you can check for any new unaddressed vulnerabilities every time your application is built. Simply include the curl command (from above) in any build.sh file. 

Contributing
------------

Contributing security advisories is as easy as it can get:

  * You can contribute a new entry by sending a pull request or by creating a
    file directly via the Github interface;

  * Create a directory based on the Composer name of the software where the
    security issue exists (use `symfony/http-foundation` for an issue in the
    Symfony HttpFoundation component for instance);

  * Each security issue must be saved in a file where the name is the CVE
    identifier (preferred) or the date when the security issue was announced
    followed by an increment (`2012-12-12-1` for instance);

  * The file is in the YAML format and **must** contain the following entries
    (have a look at existing entries for examples):

      * `title`:     A text that describes the security issue in a few words;

      * `link`:      A link to the official security issue announcement (HTTPS
        links are preferred over HTTP ones);

      * `reference`: A unique reference to identify the software (the only
        supported scheme is `composer://` followed by the Composer identifier);

      * `branches`: A hash of affected branches, where the name is the branch
        name (like `2.0.x`), and the value is a hash with the following
        entries:

          * `time`: The date and time in UTC when the security issue was fixed or null if the
            issue is not fixed yet (most of the time, the date of the **merge**
            commit that fixed the issue in the following format `2012-08-27
            19:17:44`) -- this information must be as accurate as possible as it
            is used to determine if a project is affected or not;

          * `versions`: An array of constraints describing affected versions
            for this branch (this is the same format as the one used for
            Composer -- `['>=2.0.0', '<2.0.17']`).

  * If you have a CVE identifier, add it under the `cve` key.

  * Make sure your file validates by running `php validator.php` from the root of this project.
    This script needs some dependencies to be installed via composer, so you need to
    run `composer install` before.

If some affected code is available through different Composer entries (like
when you have read-only subtree splits of a main repository), duplicate the
information in several files.

[1]: https://github.com/sensiolabs/security-checker
