"""CLI
"""
import os
import sys

import click
import ndebug

from semantic_release import ci_checks
from semantic_release.errors import ImproperConfigurationError
from .history import (evaluate_version_bump, get_current_version, get_new_version,
                      get_previous_version, set_new_version)
from .history.logs import generate_changelog, markdown_changelog
from .hvcs import check_build_status, check_token, get_domain, get_token, post_changelog
from .pypi import upload_to_pypi
from .settings import config, overload_configuration
from .vcs_helpers import (checkout, get_current_head_hash,
                          get_repository_owner_and_name, push_new_version,
                          tag_new_version, commit_new_version)

debug = ndebug.create(__name__)

SECRET_NAMES = [
    'PYPI_USERNAME',
    'PYPI_PASSWORD',
    'GH_TOKEN',
    'GL_TOKEN',
]

COMMON_OPTIONS = [
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
    click.option('--define', '-D', multiple=True,
                 help='setting="value", override a configuration value'),
    overload_configuration,
]


def common_options(func):
    """
    Decorator that adds all the options in COMMON_OPTIONS
    """
    for option in reversed(COMMON_OPTIONS):
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

    try:
        current_version = get_current_version()
    except GitError as e:
        click.echo(click.style(str(e), 'red'), err=True)
        return False

    click.echo('Current version: {0}'.format(current_version))

    if "dev" in current_version:
        master_version = current_version.split("dev")[0][:-1]
    elif "b" in current_version:
        master_version = current_version.split("b")[0]
    else:
        master_version = current_version

    set_new_version(master_version)

    if deploy_to_dev == "true":
        return deploy_dev_release(master_version, build)
    elif branch == "development":
        return deploy_beta_release(master_version, current_version, kwargs, build, retry)
    elif branch == "master":
        return deploy_production_release(master_version, current_version, retry)

    return True


def deploy_dev_release(master_version, build):
    new_version = master_version + ".dev" + build

    tag_new_version(new_version)
    set_new_version(new_version)

    click.echo('Not bumping as this is a dev build.')

    return True


def deploy_beta_release(master_version, current_version, kwargs, build, retry):
    level_bump = evaluate_version_bump(current_version, kwargs['force_level'])
    bumped_version = get_new_version(master_version, level_bump)

    new_version = bumped_version + "b" + build

    if new_version_is_not_current_version(master_version, bumped_version) and not retry:
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

    set_new_version(new_version)
    if config.get('semantic_release', 'commit_version_number', fallback=(
        config.get('semantic_release', 'version_source') == 'commit')
    ):
        commit_new_version(new_version)
    tag_new_version(new_version)

    click.echo('Bumping with a {0} version to {1}.'.format(level_bump, new_version))

    return True


def deploy_production_release(master_version, current_version, retry):
    if new_version_is_not_current_version(current_version, master_version) and not retry:
        click.echo(click.style('No release will be made.', fg='yellow'))
        return False

    if config.get('semantic_release', 'version_source') == 'commit':
        set_new_version(master_version)
    commit_new_version(master_version)
    tag_new_version(master_version)

    return True


def new_version_is_not_current_version(current_version, new_version):
    return current_version == new_version


def changelog(**kwargs):
    """
    Generates the changelog since the last release.
    :raises ImproperConfigurationError: if there is no current version
    """
    current_version = get_current_version()
    debug('changelog got current_version', current_version)

    if current_version is None:
        raise ImproperConfigurationError(
            "Unable to get the current version. "
            "Make sure semantic_release.version_variable "
            "is setup correctly"
        )
    previous_version = get_previous_version(current_version)
    debug('changelog got previous_version', previous_version)

    if kwargs['unreleased']:
        log = generate_changelog(current_version, None)
    else:
        log = generate_changelog(previous_version, current_version)
    click.echo(markdown_changelog(current_version, log, header=False))

    debug('noop={}, post={}'.format(kwargs.get('noop'), kwargs.get('post')))
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

    debug('branch=', branch)
    ci_checks.check(branch)
    checkout(branch)

    if version(**kwargs):
        push_new_version(
            auth_token=get_token(),
            owner=owner,
            name=name,
            branch=branch,
            domain=get_domain(),
        )

        if config.getboolean('semantic_release', 'upload_to_pypi'):
            upload_to_pypi(
                username=os.environ.get('PYPI_USERNAME'),
                password=os.environ.get('PYPI_PASSWORD'),
                # We are retrying, so we don't want errors for files that are already on PyPI.
                skip_existing=retry,
                remove_dist=config.getboolean('semantic_release', 'remove_dist'),
                path=config.get('semantic_release', 'dist_path'),
            )

        click.echo(click.style('New release published', 'green'))
    else:
        click.echo('Version failed, no release will be published.', err=True)


def filter_output_for_secrets(message):
    output = message
    for secret_name in SECRET_NAMES:
        secret = os.environ.get(secret_name)
        if secret != '' and secret is not None:
            output = output.replace(secret, '${}'.format(secret_name))

    return output


def entry():
    ARGS = sorted(sys.argv[1:], key=lambda x: 1 if x.startswith('--') else -1)
    main(args=ARGS)

#
# Making the CLI commands.
# We have a level of indirection to the logical commands
# so we can successfully mock them during testing
#


@click.group()
@common_options
def main(**kwargs):
    if debug.enabled:
        debug('main args:', kwargs)
        message = ''
        for secret_name in SECRET_NAMES:
            message += '{}="{}",'.format(secret_name, os.environ.get(secret_name))
        debug('main env:', filter_output_for_secrets(message))

        obj = {}
        for key in ['check_build_status', 'commit_message', 'commit_parser', 'patch_without_tag',
                    'upload_to_pypi', 'version_source']:
            val = config.get('semantic_release', key)
            obj[key] = val
        debug('main config:', obj)


@main.command(name='publish', help=publish.__doc__)
@common_options
def cmd_publish(**kwargs):
    try:
        return publish(**kwargs)
    except Exception as error:
        click.echo(click.style(filter_output_for_secrets(str(error)), 'red'), err=True)
        exit(1)


@main.command(name='changelog', help=changelog.__doc__)
@common_options
@click.option(
    '--unreleased/--released',
    help="Decides whether to show the released or unreleased changelog."
)
def cmd_changelog(**kwargs):
    try:
        return changelog(**kwargs)
    except Exception as error:
        click.echo(click.style(filter_output_for_secrets(str(error)), 'red'), err=True)
        exit(1)


@main.command(name='version', help=version.__doc__)
@common_options
def cmd_version(**kwargs):
    try:
        return version(**kwargs)
    except Exception as error:
        click.echo(click.style(filter_output_for_secrets(str(error)), 'red'), err=True)
        exit(1)


if __name__ == '__main__':
    #
    # Allow options to come BEFORE commands,
    # we simply sort them behind the command instead.
    #
    # This will have to be removed if there are ever global options
    # that are not valid for a subcommand.
    #
    entry()
