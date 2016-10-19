Jenkins CAS Plugin
==================

This is a [Jenkins](http://jenkins-ci.org) plugin providing authentication with [CAS](https://www.apereo.org/projects/cas).

Installation
------------

The latest version is available for download from the Update Center and from the [Download Site](http://updates.jenkins-ci.org/download/plugins/cas-plugin/).

For usage information, please check the [official wiki page](https://wiki.jenkins-ci.org/display/JENKINS/CAS+Plugin).

Building from source
--------------------

1. Checkout or download the source code from the current master or latest tag on GitHub.
2. Execute `mvn clean verify` from your local source code folder (install [Maven](http://maven.apache.org) if not already done).
3. Find the `cas-plugin.hpi` file in the `target` subfolder.
4. Upload it to Jenkins from the _Advanced_ tab of the _Manage Plugins_ page.

Continuous Integration builds
-----------------------------

[![Build Status](https://jenkins.ci.cloudbees.com/buildStatus/icon?job=plugins/cas-plugin)](https://jenkins.ci.cloudbees.com/job/plugins/job/cas-plugin/)

Continuous Integration builds of the official version can be found [here](https://jenkins.ci.cloudbees.com/job/plugins/job/cas-plugin/).
