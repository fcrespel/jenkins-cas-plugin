Jenkins CAS Plugin
==================

This is a [Jenkins](https://jenkins.io) plugin providing authentication with [CAS](https://www.apereo.org/projects/cas).

Installation
------------

The latest version is available for download from the Update Center and from the [Download Site](https://updates.jenkins.io/download/plugins/cas-plugin/).

For usage information, please check the [official plugin page](https://plugins.jenkins.io/cas-plugin).

Building from source
--------------------

1. Checkout or download the source code from the current master or latest tag on GitHub.
2. Execute `mvn clean verify` from your local source code folder (install [Maven](http://maven.apache.org) if not already done).
3. Find the `cas-plugin.hpi` file in the `target` subfolder.
4. Upload it to Jenkins from the _Advanced_ tab of the _Manage Plugins_ page.

Continuous Integration builds
-----------------------------

[![Build Status](https://ci.jenkins.io/buildStatus/icon?job=Plugins/cas-plugin/master)](https://ci.jenkins.io/job/Plugins/cas-plugin/master)

Continuous Integration builds of the official version can be found [here](https://ci.jenkins.io/job/Plugins/cas-plugin/master).
