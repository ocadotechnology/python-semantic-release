import re

import semver

from ..settings import config
from ..vcs_helpers import get_commit_log, get_last_master_version,\
    get_last_beta_version, get_last_dev_version
from .logs import evaluate_version_bump  # noqa

from .parser_angular import parse_commit_message as angular_parser  # noqa isort:skip
from .parser_tag import parse_commit_message as tag_parser  # noqa isort:skip


def get_current_version_by_tag(beta_version=False, dev_version=False):
    """
    Finds the current version of the package in the current working directory.
    Check tags rather than config file. return 0.0.0 if fails

    :return: A string with the version number.
    """
    if dev_version:
        version = get_last_dev_version()
    elif beta_version:
        version = get_last_beta_version()
    else:
        version = get_last_master_version()

    if version:
        return version
    else:
        return '0.0.0'


def get_current_version_by_config_file():
    filename, variable = config.get('semantic_release',
                                    'version_variable').split(':')
    variable = variable.strip()
    with open(filename, 'r') as fd:
        return re.search(
            r'^{0}\s*=\s*[\'"]([^\'"]*)[\'"]'.format(variable),
            fd.read(),
            re.MULTILINE
        ).group(1)


def get_current_version(tag=False, beta_version=False, dev_version=False):
    if tag:
        if dev_version:
            return get_current_version_by_tag(dev_version=True)
        elif beta_version:
            return get_current_version_by_tag(beta_version=True)
        else:
            return get_current_version_by_tag()
    return get_current_version_by_config_file()


def get_new_version(current_version, level_bump):
    """
    Calculates the next version based on the given bump level with semver.

    :param current_version: The version the package has now.
    :param level_bump: The level of the version number that should be bumped. Should be a `'major'`,
                       `'minor'` or `'patch'`.
    :return: A string with the next version number.
    """
    if not level_bump:
        return current_version
    return getattr(semver, 'bump_{0}'.format(level_bump))(current_version)


def get_previous_version(version):
    """
    Returns the version prior to the given version.

    :param version: A string with the version number.
    """
    if ".dev" in version:
        pattern = r'v?(\d+\.\d+\.\d+\.dev\d+)'
    elif ".b" in version:
        pattern = r'v?(\d+\.\d+\.\d+\.b\d+)'
    else:
        pattern = r'v?(\d+.\d+.\d+)'
    found_version = False
    for commit_hash, commit_message in get_commit_log():
        if version in commit_message:
            found_version = True
            continue

        if found_version:
            matches = re.match(pattern, commit_message)
            if matches:
                return matches.group(1).strip()

    if ".dev" in version:
        return get_last_dev_version([version, 'v{}'.format(version)])
    elif ".b" in version:
        return get_last_beta_version([version, 'v{}'.format(version)])
    else:
        return get_last_master_version([version, 'v{}'.format(version)])


def set_new_version(new_version):
    """
    Replaces the version number in the correct place and writes the changed file to disk.

    :param new_version: The new version number as a string.
    :return: `True` if it succeeded.
    """
    filename, variable = config.get(
        'semantic_release', 'version_variable').split(':')
    variable = variable.strip()
    with open(filename, mode='r') as fr:
        content = fr.read()

    content = re.sub(
        r'{0} ?= ?["\']\d+\.\d+\.\d+((\.dev|b)+\d+)?["\']'.format(variable),
        '{0} = \'{1}\''.format(variable, new_version),
        content
    )

    with open(filename, mode='w') as fw:
        fw.write(content)
    return True
