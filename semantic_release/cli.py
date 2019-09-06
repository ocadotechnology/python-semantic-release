import os

import click
import sys

from semantic_release import ci_checks
from semantic_release.errors import ImproperConfigurationError
from .history import (evaluate_version_bump, get_current_version, get_new_version,
                      get_previous_version, set_new_version)
from .history.logs import CHANGELOG_SECTIONS, generate_changelog, markdown_changelog
from .hvcs import check_build_status, check_token, post_changelog
from .pypi import upload_to_pypi
from .settings import config
from .vcs_helpers import (checkout, get_current_head_hash,
                          get_repository_owner_and_name, push_new_version,
                          tag_new_version, commit_new_version)

_common_options = [
    click.option('--major', 'force_level', flag_value='major', help='Force major version.'),
    click.option('--minor', 'force_level', flag_value='minor', help='Force minor version.'),
    click.option('--patch', 'force_level', flag_value='patch', help='Force patch version.'),
    click.option('--post', is_flag=True, help='Post changelog.'),
    click.option('--retry', is_flag=True, help='Retry the same release, do not bump.'),
    click.option('--noop', is_flag=True,
                 help='No-operations mode, finds the new version number without changing it.'),
    click.option('--branch', help='Travis branch the build is on.'),
    click.option('--build', help='Travis build number for beta releases.'),
    click.option('--dev', help='Whether or not the build is happening on the dev server.'),
]


def common_options(func):
    """
    Decorator that adds all the options in _common_options
    """
    for option in reversed(_common_options):
        func = option(func)
    return func


def version(**kwargs):
    """
    Detects the new version according to git log and semver. Writes the new version
    number and commits it, unless the noop-option is True.
    """
    retry = kwargs.get("retry")
    if retry:
        click.echo('Retrying publication of the same version...')
    else:
        click.echo('Creating new version..')

    build = kwargs.get("build")
    branch = kwargs.get("branch")
    deploy_to_dev = kwargs.get("dev")

    current_version = get_current_version()

    click.echo('Current version: {0}'.format(current_version))

    if "dev" in current_version:
        master_version = current_version.split("dev")[0][:-1]
    elif "b" in current_version:
        master_version = current_version.split("b")[0]
    else:
        master_version = current_version

    set_new_version(master_version)

    if deploy_to_dev == "false":
        level_bump = evaluate_version_bump(current_version, kwargs['force_level'])
        bumped_version = get_new_version(master_version, level_bump)

        if branch == "development":
            new_version = bumped_version + "b" + build
        else:
            new_version = bumped_version

        if bumped_version == master_version and not retry:
            click.echo(click.style('No release will be made.', fg='yellow'))
            return False

        if kwargs['noop'] is True:
            click.echo('{0} Should have bumped from {1} to {2}.'.format(
                click.style('No operation mode.', fg='yellow'),
                current_version,
                new_version
            ))
            return False

        if config.getboolean('semantic_release', 'check_build_status'):
            click.echo('Checking build status..')
            owner, name = get_repository_owner_and_name()
            if not check_build_status(owner, name, get_current_head_hash()):
                click.echo(click.style('The build has failed', 'red'))
                return False
            click.echo(click.style('The build was a success, continuing the release', 'green'))

        if retry:
            # No need to make changes to the repo, we're just retrying.
            return True

        if config.get('semantic_release', 'version_source') == 'commit':
            set_new_version(new_version)
        commit_new_version(new_version)
        tag_new_version(new_version)

        click.echo('Bumping with a {0} version to {1}.'.format(level_bump, new_version))

    else:
        new_version = master_version + ".dev" + build

        tag_new_version(new_version)
        set_new_version(new_version)

        click.echo('Not bumping as this is a dev build.')

    return True


def changelog(**kwargs):
    """
    Generates the changelog since the last release.
    """
    current_version = get_current_version()
    if current_version is None:
        raise ImproperConfigurationError(
            "Unable to get the current version. "
            "Make sure semantic_release.version_variable "
            "is setup correctly"
        )
    previous_version = get_previous_version(current_version)

    log = generate_changelog(previous_version,  current_version)
    for section in CHANGELOG_SECTIONS:
        if not log[section]:
            continue

        click.echo(section.capitalize())
        click.echo(''.join(['-' for i in range(len(section))]))
        for item in log[section]:
            click.echo(' - {0} ({1})'.format(item[1], item[0]))
        click.echo('\n')

    if not kwargs.get('noop') and kwargs.get('post'):
        if check_token():
            owner, name = get_repository_owner_and_name()
            click.echo('Updating changelog')
            post_changelog(
                owner,
                name,
                current_version,
                markdown_changelog(current_version, log, header=False)
            )
        else:
            click.echo(
                click.style('Missing token: cannot post changelog', 'red'), err=True)


def publish(**kwargs):
    """
    Runs the version task before pushing to git and uploading to pypi.
    """
    branch = kwargs.get("branch")
    retry = kwargs.get("retry")
    owner, name = get_repository_owner_and_name()

    ci_checks.check(branch)
    checkout(branch)

    if version(**kwargs):
        push_new_version(
            branch,
            gh_token=os.environ.get('GH_TOKEN'),
            owner=owner,
            name=name,
        )

        if config.getboolean('semantic_release', 'upload_to_pypi'):
            upload_to_pypi(
                username=os.environ.get('PYPI_USERNAME'),
                password=os.environ.get('PYPI_PASSWORD'),
                # We are retrying, so we don't want errors for files that are already on PyPI.
                skip_existing=retry,
            )

        click.echo(click.style('New release published', 'green'))
    else:
        click.echo('Version failed, no release will be published.', err=True)


#
# Making the CLI commands.
# We have a level of indirection to the logical commands
# so we can successfully mock them during testing
#

@click.group()
@common_options
def main(**kwargs):
    pass


@main.command(name='publish', help=publish.__doc__)
@common_options
def cmd_publish(**kwargs):
    return publish(**kwargs)


@main.command(name='changelog', help=changelog.__doc__)
@common_options
def cmd_changelog(**kwargs):
    return changelog(**kwargs)


@main.command(name='version', help=version.__doc__)
@common_options
def cmd_version(**kwargs):
    return version(**kwargs)


if __name__ == '__main__':
    #
    # Allow options to come BEFORE commands,
    # we simply sort them behind the command instead.
    #
    # This will have to be removed if there are ever global options
    # that are not valid for a subcommand.
    #
    args = sorted(sys.argv[1:], key=lambda x: 1 if x.startswith('--') else -1)
    main(args=args)
