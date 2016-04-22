# Contributing

Thanks a lot for participating in this project.

## Prerequisites

Be sure to have the Java JDK 8 installed on your system.

## Prepare Your Repository

Fork, then clone the repository:

	git clone git@github.com:YOUR-REPO/vaderetro-provider.git

Set the upstream remote:

	git remote add upstream git@github.com:VadeRetro/vaderetro-provider.git

Please, check the project is passing unit tests:

	mvn clean install

## Add Your Contribution

To contribute, just create a branch from the `devel` branch, representing the current development. Please, follow these little rules about the branch naming:
* if you want to add a feature, create a branch with a name prefixed by `feature_`, followed by the name of the feature
* if you want to add a bug fix, create a branch with a name prefixed by `fix_`, followed by the name of the bug fix.

As an example, for a feature called `myFeature`, create the new branch this way:

	git checkout -b feature_myFeature upstream/devel

Before a pull request, always check the project is passing unit tests. You must add your own unit tests if you're contributing with a new feature.

Then, when doing your pull request, add a documentation about your contribution. Without it, your pull request may be rejected.  

## About Project Versions

Never change the version number of the project, it will be done by the project manager at `devel` and `master` branch updates.
