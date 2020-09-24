"""Test module for Dashboard UI

:Requirement: Dashboard

:CaseAutomation: Automated

:CaseLevel: Acceptance

:CaseComponent: Dashboard

:TestType: Functional

:CaseImportance: High

:Upstream: No
"""
from airgun.session import Session
from nailgun import entities
from nailgun.entity_mixins import TaskFailedError
from pytest import raises

from robottelo.api.utils import create_role_permissions
from robottelo.config import settings
from robottelo.constants import DISTRO_RHEL7
from robottelo.constants import FAKE_1_CUSTOM_PACKAGE
from robottelo.constants import FAKE_2_ERRATA_ID
from robottelo.constants.repos import FAKE_6_YUM_REPO
from robottelo.datafactory import gen_string
from robottelo.decorators import run_in_one_thread
from robottelo.decorators import skip_if
from robottelo.decorators import skip_if_not_set
from robottelo.decorators import tier2
from robottelo.decorators import tier3
from robottelo.decorators import upgrade
from robottelo.products import RepositoryCollection
from robottelo.products import SatelliteToolsRepository
from robottelo.products import YumRepository
from robottelo.utils.issue_handlers import is_open
from robottelo.vm import VirtualMachine


@tier2
def test_positive_host_configuration_status(session):
    """Check if the Host Configuration Status Widget links are working

    :id: ffb0a6a1-2b65-4578-83c7-61492122d865

    :Steps:

        1. Navigate to Monitor -> Dashboard
        2. Review the Host Configuration Status
        3. Navigate to each of the links which has search string associated
           with it.

    :expectedresults: Each link shows the right info

    :BZ: 1631219

    :CaseLevel: Integration
    """
    org = entities.Organization().create()
    loc = entities.Location().create()
    host = entities.Host(organization=org, location=loc).create()
    criteria_list = [
        'Hosts that had performed modifications without error',
        'Hosts in error state',
        'Good host reports in the last 30 minutes',
        'Hosts that had pending changes',
        'Out of sync hosts',
        'Hosts with alerts disabled',
        'Hosts with no reports',
    ]
    search_strings_list = [
        'last_report > \"30 minutes ago\" and (status.applied > 0 or'
        ' status.restarted > 0) and (status.failed = 0)',
        'last_report > \"30 minutes ago\" and (status.failed > 0 or'
        ' status.failed_restarts > 0) and status.enabled = true',
        'last_report > \"30 minutes ago\" and status.enabled = true and'
        ' status.applied = 0 and status.failed = 0 and status.pending = 0',
        'last_report > \"30 minutes ago\" and status.pending > 0 and status.enabled = true',
        'last_report < \"30 minutes ago\" and status.enabled = true',
        'status.enabled = false',
        'not has last_report and status.enabled = true',
    ]
    if is_open('BZ:1631219'):
        criteria_list.pop()
        search_strings_list.pop()

    with session:
        session.organization.select(org_name=org.name)
        session.location.select(loc_name=loc.name)
        dashboard_values = session.dashboard.read('HostConfigurationStatus')
        for criteria in criteria_list:
            if criteria == 'Hosts with no reports':
                assert dashboard_values['status_list'][criteria] == 1
            else:
                assert dashboard_values['status_list'][criteria] == 0

        for criteria, search in zip(criteria_list, search_strings_list):
            if criteria == 'Hosts with no reports':
                session.dashboard.action({'HostConfigurationStatus': {'status_list': criteria}})
                values = session.host.read_all()
                assert values['searchbox'] == search
                assert len(values['table']) == 1
                assert values['table'][0]['Name'] == host.name
            else:
                session.dashboard.action({'HostConfigurationStatus': {'status_list': criteria}})
                values = session.host.read_all()
                assert values['searchbox'] == search
                assert len(values['table']) == 0


@tier2
def test_positive_host_configuration_chart(session):
    """Check if the Host Configuration Chart is working in the Dashboard UI

    :id: b03314aa-4394-44e5-86da-c341c783003d

    :Steps:

        1. Navigate to Monitor -> Dashboard
        2. Review the Host Configuration Chart widget
        3. Check that chart contains correct percentage value

    :expectedresults: Chart showing correct data

    :CaseLevel: Integration
    """
    org = entities.Organization().create()
    loc = entities.Location().create()
    entities.Host(organization=org, location=loc).create()
    with session:
        session.organization.select(org_name=org.name)
        session.location.select(loc_name=loc.name)
        dashboard_values = session.dashboard.read('HostConfigurationChart')
        assert dashboard_values['chart'][''] == '100%'


@upgrade
@run_in_one_thread
@tier2
def test_positive_task_status(session):
    """Check if the Task Status is working in the Dashboard UI and
        filter from Tasks index page is working correctly

    :id: fb667d6a-7255-4341-9f79-2f03d19e8e0f

    :Steps:

        1. Navigate to Monitor -> Dashboard
        2. Review the Latest Warning/Error Tasks widget
        3. Review the Running Chart widget
        4. Review the Task Status widget
        5. Review the Stopped Chart widget
        6. Click few links from the widget

    :expectedresults: Each link shows the right info and filter can be set
        from Tasks dashboard

    :BZ: 1718889

    :CaseLevel: Integration
    """
    url = 'http://www.non_existent_repo_url.org/repos'
    org = entities.Organization().create()
    product = entities.Product(organization=org).create()
    repo = entities.Repository(url=url, product=product, content_type='puppet').create()
    with raises(TaskFailedError):
        repo.sync()
    with session:
        session.organization.select(org_name=org.name)
        session.dashboard.action({'TaskStatus': {'state': 'stopped', 'result': 'warning'}})
        searchbox = session.task.read_all('searchbox')
        assert searchbox['searchbox'] == 'state=stopped&result=warning'
        session.task.set_chart_filter('ScheduledChart')
        tasks = session.task.read_all(['pagination', 'ScheduledChart'])
        assert tasks['pagination']['total_items'] == tasks['ScheduledChart']['total'].split()[0]
        session.task.set_chart_filter('StoppedChart', {'row': 1, 'focus': 'Total'})
        tasks = session.task.read_all()
        assert tasks['pagination']['total_items'] == tasks['StoppedChart']['table'][1]['Total']
        task_name = "Synchronize repository '{}'; product '{}'; organization '{}'".format(
            repo.name, product.name, org.name
        )
        assert tasks['table'][0]['Action'] == task_name
        assert tasks['table'][0]['State'] == 'stopped'
        assert tasks['table'][0]['Result'] == 'warning'
        session.dashboard.action({'LatestFailedTasks': {'name': 'Synchronize'}})
        values = session.task.read(task_name)
        assert values['task']['result'] == 'warning'
        assert values['task']['errors'] == 'PLP0000: Importer indicated a failed response'


@upgrade
@run_in_one_thread
@skip_if_not_set('clients')
@tier3
@skip_if(not settings.repos_hosting_url)
def test_positive_user_access_with_host_filter(test_name, module_loc):
    """Check if user with necessary host permissions can access dashboard
    and required widgets are rendered with proper values

    :id: 24b4b371-cba0-4bc8-bc6a-294c62e0586d

    :Steps:

        1. Specify proper filter with permission for your role
        2. Create new user and assign role to it
        3. Login into application using this new user
        4. Check dashboard and widgets on it
        5. Register new content host to populate some values into dashboard widgets

    :expectedresults: Dashboard and Errata Widget rendered without errors and
        contain proper values

    :BZ: 1417114

    :CaseLevel: System
    """
    user_login = gen_string('alpha')
    user_password = gen_string('alphanumeric')
    org = entities.Organization().create()
    lce = entities.LifecycleEnvironment(organization=org).create()
    # create a role with necessary permissions
    role = entities.Role().create()
    user_permissions = {
        'Organization': ['view_organizations'],
        'Location': ['view_locations'],
        None: ['access_dashboard'],
        'Host': ['view_hosts'],
    }
    create_role_permissions(role, user_permissions)
    # create a user and assign the above created role
    entities.User(
        default_organization=org,
        organization=[org],
        default_location=module_loc,
        location=[module_loc],
        role=[role],
        login=user_login,
        password=user_password,
    ).create()
    with Session(test_name, user=user_login, password=user_password) as session:
        assert session.dashboard.read('HostConfigurationStatus')['total_count'] == 0
        assert len(session.dashboard.read('LatestErrata')) == 0
        repos_collection = RepositoryCollection(
            distro=DISTRO_RHEL7,
            repositories=[SatelliteToolsRepository(), YumRepository(url=FAKE_6_YUM_REPO)],
        )
        repos_collection.setup_content(org.id, lce.id)
        with VirtualMachine(distro=repos_collection.distro) as client:
            repos_collection.setup_virtual_machine(client)
            result = client.run('yum install -y {0}'.format(FAKE_1_CUSTOM_PACKAGE))
            assert result.return_code == 0
            hostname = client.hostname
            # Check UI for values
            assert session.host.search(hostname)[0]['Name'] == hostname
            hosts_values = session.dashboard.read('HostConfigurationStatus')
            assert hosts_values['total_count'] == 1
            errata_values = session.dashboard.read('LatestErrata')['erratas']
            assert len(errata_values) == 1
            assert errata_values[0]['Type'] == 'security'
            assert FAKE_2_ERRATA_ID in errata_values[0]['Errata']
