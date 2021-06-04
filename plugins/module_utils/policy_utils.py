#!/usr/bin/env python3
#
# Copyright 2021 Venafi, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#  http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
from vcert.policy import PolicySpecification

ERR_MSG = 'Fields do not match. Local: %s. Remote: %s.'
EMPTY_MSG = '%s structure is empty on %s but exists on %s.'
LOCAL = 'Local'
REMOTE = 'Remote'


def _get_err_msg(local, remote):
    if isinstance(local, list):
        return ERR_MSG % (','.join(local), ','.join(remote))
    else:
        return ERR_MSG % (local, remote)


def _get_empty_msg(name, empty_type):
    """

    :param str name:
    :param str empty_type:
    :rtype: str
    """
    if empty_type == LOCAL:
        return EMPTY_MSG % (name, LOCAL, REMOTE)
    elif empty_type == REMOTE:
        return EMPTY_MSG % (name, REMOTE, LOCAL)
    return ''


def check_policy_specification(local_ps, remote_ps):
    """
    Validates that all values present in the source PolicySpecification match with
    the current output PolicySpecification
    :param PolicySpecification local_ps:
    :param PolicySpecification remote_ps:
    :rtype: tuple[bool, list[str]]
    """
    is_changed = False
    msgs = []
    if not _check_list(remote_ps.owners, local_ps.owners):
        is_changed = True
        msgs.append(_get_err_msg(local_ps.owners, remote_ps.owners))
    if not _check_list(remote_ps.users, local_ps.users):
        is_changed = True
        msgs.append(_get_err_msg(local_ps.users, remote_ps.users))
    if not _check_list(remote_ps.approvers, local_ps.approvers):
        is_changed = True
        msgs.append(_get_err_msg(local_ps.approvers, remote_ps.approvers))
    if not _check_value(remote_ps.user_access, local_ps.user_access):
        is_changed = True
        msgs.append(_get_err_msg(local_ps.user_access, remote_ps.user_access))

    # Validating Policy
    if _is_empty_object(local_ps.policy) and not _is_empty_object(remote_ps.policy):
        is_changed = True
        msgs.append(_get_empty_msg('Policy', LOCAL))
    elif not _is_empty_object(local_ps.policy) and _is_empty_object(remote_ps.policy):
        is_changed = True
        msgs.append(_get_empty_msg('Policy', REMOTE))
    else:
        local_p = local_ps.policy
        remote_p = remote_ps.policy
        if not _check_list(remote_p.domains, local_p.domains):
            is_changed = True
            msgs.append('FFF')
        for src, out in {(local_p.wildcard_allowed, remote_p.wildcard_allowed),
                         (local_p.max_valid_days, remote_p.max_valid_days),
                         (local_p.certificate_authority, remote_p.certificate_authority),
                         (local_p.auto_installed, remote_p.auto_installed)}:
            if not _check_value(out, src):
                is_changed = True
                msgs.append('GGG')

        # Validating Policy.Subject
        if _is_empty_object(local_p.subject) and not _is_empty_object(remote_p.subject):
            is_changed = True
            msgs.append(_get_empty_msg('Policy.Subject', LOCAL))
        elif not _is_empty_object(local_p.subject) and _is_empty_object(remote_p.subject):
            is_changed = True
            msgs.append(_get_empty_msg('Policy.Subject', REMOTE))
        else:
            local_subject = local_p.subject
            remote_subject = remote_p.subject
            for src, out in [(local_subject.orgs, remote_subject.orgs),
                             (local_subject.org_units, remote_subject.org_units),
                             (local_subject.localities, remote_subject.localities),
                             (local_subject.states, remote_subject.states),
                             (local_subject.countries, remote_subject.countries)]:
                if not _check_list(out, src):
                    is_changed = True
                    msgs.append('III')

        # Validating Policy.KeyPair
        if _is_empty_object(local_p.key_pair) and not _is_empty_object(remote_p.key_pair):
            is_changed = True
            msgs.append(_get_empty_msg('Policy.KeyPair', LOCAL))
        elif not _is_empty_object(local_p.key_pair) and _is_empty_object(remote_p.key_pair):
            is_changed = True
            msgs.append(_get_empty_msg('Policy.KeyPair', REMOTE))
        else:
            local_kp = local_p.key_pair
            remote_kp = remote_p.key_pair
            for src, out in [(local_kp.service_generated, remote_kp.service_generated),
                             (local_kp.reuse_allowed, remote_kp.reuse_allowed)]:
                if not _check_value(out, src):
                    is_changed = True
                    msgs.append('LLL')
            # if not _check_key_types(out_kp.key_types, local_kp.key_types):
            #     is_changed = True
            #     msgs.append('M2M2M2')
            for src, out in [(local_kp.key_types, remote_kp.key_types),
                             (local_kp.rsa_key_sizes, remote_kp.rsa_key_sizes),
                             (local_kp.elliptic_curves, remote_kp.elliptic_curves)]:
                if not _check_list(out, src):
                    is_changed = True
                    msgs.append(_get_err_msg(src, out))

        # Validating Policy.SubjectAltNames
        if _is_empty_object(local_p.subject_alt_names) and not _is_empty_object(remote_p.subject_alt_names):
            is_changed = True
            msgs.append(_get_empty_msg('Policy.SubjectAltNames', LOCAL))
        elif not _is_empty_object(local_p.subject_alt_names) and _is_empty_object(remote_p.subject_alt_names):
            is_changed = True
            msgs.append(_get_empty_msg('Policy.SubjectAltNames', REMOTE))
        else:
            local_sans = local_p.subject_alt_names
            remote_sans = remote_p.subject_alt_names
            for src, out in [(local_sans.dns_allowed, remote_sans.dns_allowed),
                             (local_sans.email_allowed, remote_sans.email_allowed),
                             (local_sans.ip_allowed, remote_sans.ip_allowed),
                             (local_sans.upn_allowed, remote_sans.upn_allowed),
                             (local_sans.uri_allowed, remote_sans.uri_allowed)]:
                if not _check_value(out, src):
                    is_changed = True
                    msgs.append('OOO')

    # Validating Defaults
    if _is_empty_object(local_ps.defaults) and not _is_empty_object(remote_ps.defaults):
        is_changed = True
        msgs.append(_get_empty_msg('Defaults', LOCAL))
    elif not _is_empty_object(local_ps.defaults) and _is_empty_object(remote_ps.defaults):
        is_changed = True
        msgs.append(_get_empty_msg('Defaults', REMOTE))
    else:
        local_d = local_ps.defaults
        remote_d = remote_ps.defaults
        for src, out in [(local_d.domain, remote_d.domain),
                         (local_d.auto_installed, remote_d.auto_installed)]:
            if not _check_value(out, src):
                is_changed = True
                msgs.append('RRR')

        # Validating Defaults.DefaultSubject
        if _is_empty_object(local_d.subject) and not _is_empty_object(remote_d.subject):
            is_changed = True
            msgs.append(_get_empty_msg('Defaults.DefaultSubject', LOCAL))
        elif not _is_empty_object(remote_d.subject) and _is_empty_object(remote_d.subject):
            is_changed = True
            msgs.append(msgs.append('Defaults.DefaultSubject', REMOTE))
        else:
            local_ds = local_d.subject
            remote_ds = remote_d.subject
            if not _check_list(remote_ds.org_units, local_ds.org_units):
                is_changed = True
                msgs.append('TTT')
            for src, out in [(local_ds.org, remote_ds.org),
                             (local_ds.locality, remote_ds.locality),
                             (local_ds.state, remote_ds.state),
                             (local_ds.country, remote_ds.country)]:
                if not _check_value(out, src):
                    is_changed = True
                    msgs.append('UUU')

        # Validating Defaults.DefaultKeyPair
        if _is_empty_object(local_d.key_pair) and not _is_empty_object(remote_d.key_pair):
            is_changed = True
            msgs.append(_get_empty_msg('Defaults.DefaultKeyPair', LOCAL))
        elif not _is_empty_object(local_d.key_pair) and _is_empty_object(remote_d.key_pair):
            is_changed = True
            msgs.append(_get_empty_msg('Defaults.DefaultKeyPair', REMOTE))
        else:
            src_dkp = local_d.key_pair
            out_dkp = remote_d.key_pair
            for src, out in [(src_dkp.elliptic_curve, out_dkp.elliptic_curve),
                             (src_dkp.key_type, out_dkp.key_type),
                             (src_dkp.rsa_key_size, out_dkp.rsa_key_size),
                             (src_dkp.service_generated, out_dkp.service_generated)]:
                if not _check_value(out, src):
                    is_changed = True
                    msgs.append('XXX')

    return is_changed, msgs


def _is_empty_object(obj):
    """

    :param object obj:  The object to check
    :return: True if and only if all the object's fields' values are None, empty or equivalent. False otherwise
    :rtype: bool
    """
    if obj is None:
        return True
    for k, v in obj.__dict__.items():
        if v is None:
            continue
        if isinstance(v, int):
            return False
        elif isinstance(v, str):
            if v != '':
                return False
            else:
                continue
        elif isinstance(v, bool):
            return False
        elif isinstance(v, list):
            if len(v) > 0:
                return False
            else:
                continue
        else:
            if not _is_empty_object(v):
                return False
    return True


def _check_list(remote_values, local_values):
    """
    Tests that all the elements of the sublist are present in the collection

    :param list remote_values: The tested values
    :param list local_values: The member values
    :rtype: bool
    """
    if len(remote_values) == len(local_values):
        return all(x in local_values for x in remote_values)
    else:
        return False


def _check_value(remote_value, local_value):
    """
    Validates if both parameters are equal.

    :param remote_value:
    :param local_value:
    :return: True if both parameters hold the same value, False otherwise
    :rtype: bool
    """
    if remote_value is not None and local_value is not None:
        return True if remote_value == local_value else False
    elif remote_value is None and local_value is None:
        return True
    else:
        return False


def _check_key_types(remote_values, local_values):
    """
    Validates that the key types match regardless of the casing. E.g. 'RSA' == 'rsa'
    :param list[str] remote_values:
    :param list[str] local_values:
    :rtype: bool
    """
    copy = []
    for val in local_values:
        copy.append(val.upper())
    if len(remote_values) == len(local_values):
        return all(x.upper() in copy for x in remote_values)
    else:
        return False

