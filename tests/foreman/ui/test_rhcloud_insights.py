"""Tests for RH Cloud - Inventory

:Requirement: RHCloud

:CaseAutomation: Automated

:CaseComponent: RHCloud

:Team: Proton

:CaseImportance: High

"""

from datetime import UTC, datetime

import pytest
from wait_for import wait_for

from robottelo.config import settings
from robottelo.constants import DNF_RECOMMENDATION, OPENSSH_RECOMMENDATION


def create_recommendation(host):
    """Function to create recommendation rule hits that can be remediated."""

    # Add rule hit for DNF_RECOMMENDATION (RHEL 8+)
    if host.os_version.major > 7:
        host.run('dnf update -y dnf;sed -i -e "/^best/d" /etc/dnf/dnf.conf')

    # Add rule hit for SSH_RECOMMENDATION
    host.run('chmod 777 /etc/ssh/sshd_config')

    # Upload data
    result = host.run('insights-client')
    assert result.status == 0


def sync_recommendations(session, satellite):
    timestamp = datetime.now(UTC).strftime('%Y-%m-%d %H:%M')
    session.cloudinsights.sync_hits()
    wait_for(
        lambda: (
            satellite.api.ForemanTask()
            .search(
                query={'search': f'Red Hat Lightspeed full sync and started_at >= "{timestamp}"'}
            )[0]
            .result
            == 'success'
        ),
        timeout=180,
        delay=15,
        handle_exception=True,
    )


@pytest.mark.e2e
@pytest.mark.pit_server
@pytest.mark.pit_client
@pytest.mark.no_containers
@pytest.mark.rhel_ver_match('N-1')
def test_rhcloud_insights_e2e(
    rhel_insights_vm,
    rhcloud_manifest_org,
    module_target_sat_insights,
):
    """Synchronize hits data from hosted, verify results are displayed in Satellite, and run remediation.

    :id: d952e83c-3faf-4299-a048-2eb6ccb8c9c2

    :steps:
        1. Prepare misconfigured machine and upload its data to Red Hat Lightspeed.
        2. In Satellite UI, go to Red Hat Lightspeed > Recommendations.
        3. Run remediation for "OpenSSH config permissions" recommendation against host.
        4. Verify that the remediation job completed successfully.
        5. Re-sync recommendations.
        6. Search for previously remediated issue.

    :expectedresults:
        1. Recommendation related to "OpenSSH config permissions" issue is listed
            for misconfigured machine.
        2. Remediation job finished successfully.
        3. Recommendation related to "OpenSSH config permissions" issue is not listed.

    :CaseImportance: Critical

    :BZ: 1965901, 1962048, 1976754

    :Verifies: SAT-36449

    :customerscenario: true

    :parametrized: yes

    :CaseAutomation: Automated
    """
    org_name = rhcloud_manifest_org.name

    # Query for searching the available recommendation
    REC_QUERY = f'hostname = "{rhel_insights_vm.hostname}" and title = "{OPENSSH_RECOMMENDATION}"'

    # Verify insights-client can update to latest version available from server
    assert rhel_insights_vm.execute('insights-client --version').status == 0

    # Prepare misconfigured machine and upload data to Red Hat Lightspeed
    create_recommendation(rhel_insights_vm)

    with module_target_sat_insights.ui_session() as session:
        session.organization.select(org_name=org_name)

        # Sync the recommendations
        sync_recommendations(session, module_target_sat_insights)

        # Verify that we can see the rule hit via insights-client
        result = rhel_insights_vm.execute('insights-client --diagnosis')
        assert result.status == 0
        assert 'OPENSSH_HARDENING_CONFIG_PERMS' in result.stdout

        # Verify that errors are not present in production.log (SAT-36449)
        result = module_target_sat_insights.execute(
            'grep "500 Internal Server Error" /var/log/foreman/production.log'
        )
        assert result.status != 0
        result = module_target_sat_insights.execute(
            'grep "uninitialized constant" /var/log/foreman/production.log'
        )
        assert result.status != 0

        # Search for the recommendation.
        result = session.cloudinsights.search(REC_QUERY)[0]
        assert result['Hostname'] == rhel_insights_vm.hostname
        assert result['Recommendation'] == OPENSSH_RECOMMENDATION

        # Run the remediation.
        session.cloudinsights.remediate(OPENSSH_RECOMMENDATION)
        session.jobinvocation.wait_job_invocation_state(
            entity_name='Insights remediations for selected issues',
            host_name=rhel_insights_vm.hostname,
        )

        # Re-sync the recommendations
        sync_recommendations(session, module_target_sat_insights)

        # Verify that the recommendation is not listed anymore.
        assert not session.cloudinsights.search(REC_QUERY)


@pytest.mark.e2e
@pytest.mark.no_containers
@pytest.mark.rhel_ver_list([10])
def test_rhcloud_insights_remediate_multiple_hosts(
    rhel_insights_vms,
    rhcloud_manifest_org,
    module_target_sat_insights,
):
    """Get rule hits data for multiple Hosts from hosted Red Hat Lightspeed Advisor, verify results are displayed in Satellite, and run remediations for all Hosts simultaneously.

    :id: 33463576-ccc0-4200-a5c0-6e7ffc9a03f7

    :steps:
        1. Prepare misconfigured machines and upload data to hosted Red Hat Lightspeed Advisor.
        2. In Satellite UI, go to Red Hat Lightspeed > Recommendations.
        3. Run remediation for "OpenSSH config permissions" recommendation against Hosts.
        4. Verify that the remediation jobs completed successfully.
        5. Refresh the recommendations from Red Hat Lightspeed.
        6. Search for previously remediated issues.
    :expectedresults:
        1. Recommendations related to "OpenSSH config permissions" issue are listed
            for misconfigured machines.
        2. Remediation jobs finished successfully.
        3. Recommendations related to "OpenSSH config permissions" issue are not listed.

    :CaseImportance: Critical

    :parametrized: yes

    :CaseAutomation: Automated
    """
    org_name = rhcloud_manifest_org.name
    hostnames = [host.hostname for host in rhel_insights_vms]

    # Query for searching the available recommendations
    REC_QUERY = f'hostname ^ ({",".join(hostnames)}) and title = "{OPENSSH_RECOMMENDATION}"'

    # Query for searching the scheduled remediation tasks
    TASK_QUERY = (
        f'Remote action: Insights remediations for selected issues on ({"|".join(hostnames)})'
    )

    # Prepare the misconfigured hosts and upload dats
    for vm in rhel_insights_vms:
        create_recommendation(vm)

    with module_target_sat_insights.ui_session() as session:
        session.organization.select(org_name=org_name)

        # Sync the recommendations
        sync_recommendations(session, module_target_sat_insights)

        # Search for the recommendations
        results = session.cloudinsights.search(REC_QUERY)

        assert len(results) == len(rhel_insights_vms)
        assert all(result['Hostname'] in hostnames for result in results)
        assert all(result['Recommendation'] == OPENSSH_RECOMMENDATION for result in results)

        # Run the remediation for all hosts matching this rule
        timestamp = datetime.now(UTC).strftime('%Y-%m-%d %H:%M')
        session.cloudinsights.remediate(OPENSSH_RECOMMENDATION)

        def verify_tasks():
            tasks = session.task.search(f'{TASK_QUERY} and start_at >= "{timestamp}"')
            assert all(task['Result'] != 'error' for task in tasks)
            return len(tasks) == len(rhel_insights_vms) and all(
                task['Result'] == 'success' for task in tasks
            )

        # Wait for the remediation tasks to complete.
        wait_for(
            lambda: verify_tasks(),
            timeout=120,
            delay=15,
            handle_exception=True,
        )

        # Re-sync the recommendations
        sync_recommendations(session, module_target_sat_insights)

        # Verify that the recommendations are not listed anymore.
        assert not session.cloudinsights.search(REC_QUERY)


@pytest.mark.stubbed
def test_insights_reporting_status():
    """Verify that the Red Hat Lightspeed reporting status functionality works as expected.

    :id: 75629a08-b585-472b-a295-ce497075e519

    :steps:
        1. Register a satellite content host with Red Hat Lightspeed.
        2. Change 48 hours of wait time to 4 minutes in insights_client_report_status.rb file.
            See foreman_rh_cloud PR#596.
        3. Unregister host from Red Hat Lightspeed.
        4. Wait 4 minutes.
        5. Use ForemanTasks.sync_task(InsightsCloud::Async::InsightsClientStatusAging)
            execute task manually.

    :expectedresults:
        1. Status for host changed to "Not reporting".

    :CaseImportance: Medium

    :BZ: 1976853

    :CaseAutomation: ManualOnly
    """


@pytest.mark.stubbed
def test_recommendation_sync_for_satellite():
    """Verify that recommendations are listed for satellite.

    :id: ee3feba3-c255-42f1-8293-b04d540dcca5

    :steps:
        1. Register Satellite with Red Hat Lightspeed. (satellite-installer --register-with-insights)
        2. Add RH cloud token in settings.
        3. Go to Red Hat Lightspped > Recommendations > Click on Sync recommendations button.
        4. Click on notification icon.
        5. Select recommendation and try remediating it.

    :expectedresults:
        1. Notification about recommendations for Satellite is shown.
        2. Recommendations are listed for satellite.
        3. Successfully remediated the recommendation for Satellite itself.

    :CaseImportance: High

    :BZ: 1978182

    :CaseAutomation: ManualOnly
    """


@pytest.mark.stubbed
def test_host_sorting_based_on_recommendation_count():
    """Verify that hosts can be sorted and filtered based on recommendation count.

    :id: b1725ec1-60db-422e-809d-f81d99ae156e

    :steps:
        1. Register a few Satellite content host with Red Hat Lightspeed.
        2. Sync recommendations.
        3. Go to Hosts > All Hosts.
        4. Click on "Recommendations" column.
        5. Use insights_recommendations_count keyword to filter hosts.

    :expectedresults:
        1. Hosts are sorted based on recommendations count.
        2. Hosts are filtered based on insights_recommendations_count.

    :CaseImportance: Low

    :BZ: 1889662

    :CaseAutomation: ManualOnly
    """


@pytest.mark.no_containers
@pytest.mark.rhel_ver_match('N-0')
def test_host_details_page(
    rhel_insights_vm,
    rhcloud_manifest_org,
    module_target_sat_insights,
):
    """Test host details page for host with recommendations.

    :id: e079ed10-c9f5-4331-9cb3-70b224b1a584

    :customerscenario: true

    :steps:
        1. Prepare misconfigured machine and upload its data to Red Hat Lightspeed.
        2. Sync recommendations.
        3. Sync inventory status.
        4. Go to Hosts -> All Hosts
        5. Verify there is a "Recommendations" column containing recommendation count.
        6. Check popover status of host.
        7. Verify that host properties shows "reporting" inventory upload status.
        8. Read the recommendations listed in the Recommendations tab present on the host details page.
        9. Click on "Recommendations" tab.
        10. Try to delete host.

    :expectedresults:
        1. There's a Recommendations column with the correct number of recommendations.
        2. Inventory upload status is displayed in popover status of host.
        3. Red Hat Lightspeed registration status is displayed in popover status of host.
        4. Inventory upload status is present in host properties table.
        5. Verify the contents of the Recommendations tab.
        6. Clicking on the "Recommendations" tab takes the user to the Recommendations page with the
            recommendations selected for that host.
        7. Host with recommendations is deleted from Satellite.

    :BZ: 1974578, 1860422, 1928652, 1865876, 1879448

    :parametrized: yes

    :CaseAutomation: Automated
    """
    org_name = rhcloud_manifest_org.name

    # Prepare misconfigured machine and upload data to Red Hat Lightspeed.
    create_recommendation(rhel_insights_vm)

    with module_target_sat_insights.ui_session() as session:
        session.organization.select(org_name=org_name)

        # Ensure the "Recommendations" column is present.
        session.all_hosts.manage_table_columns(
            {
                'Recommendations': True,
            }
        )

        # Sync recommendations from Red Hat Lightspeed.
        sync_recommendations(session, module_target_sat_insights)

        # Verify status of host.
        result = session.host_new.get_host_statuses(rhel_insights_vm.hostname)
        assert result['Red Hat Lightspeed']['Status'] == 'Reporting'
        assert (
            result['Inventory']['Status']
            == 'Host is uploaded and present on console.redhat.com Inventory service'
        )

        # Verify recommendations exist for host.
        result = session.host_new.search(rhel_insights_vm.hostname)[0]
        assert result['Name'] == rhel_insights_vm.hostname
        assert int(result['Recommendations']) > 0

        # Read the recommendations on the host details page's Recommendation tab.
        recommendations = session.host_new.get_recommendations(rhel_insights_vm.hostname)
        assert len(recommendations), 'No recommendations were found'
        assert int(result['Recommendations']) == len(recommendations)

        # Verify
        for recommendation in recommendations:
            if recommendation['Recommendation'] == DNF_RECOMMENDATION:
                assert recommendation['Total risk'] == 'Moderate'
                assert DNF_RECOMMENDATION in recommendation['Recommendation']

    # Delete host
    rhel_insights_vm.nailgun_host.delete()
    assert not rhel_insights_vm.nailgun_host


@pytest.mark.e2e
@pytest.mark.pit_client
@pytest.mark.no_containers
# last 2 rhel versions with fips
@pytest.mark.rhel_ver_list(settings.supportability.content_hosts.rhel.versions[-4:])
def test_insights_registration_with_capsule(
    rhcloud_capsule,
    rhcloud_activation_key,
    rhcloud_manifest_org,
    module_target_sat_insights,
    rhel_contenthost,
    default_os,
):
    """Registering host with Red Hat Lightspeed through external capsule,
    and also test rh_cloud_insights:clean_statuses rake command.

    :id: 9db1d307-664c-4d4a-89de-da986224f071

    :customerscenario: true

    :steps:
        1. Integrate a capsule with satellite.
        2. Open the global registration form and select the same capsule.
        3. Override Red Hat Lightspeed and Rex parameters.
        4. Check host is registered successfully with selected capsule.
        5. Test insights client connection & reporting status.
        6. Verify Remote Execution is functional by running a job on the host.
        7. Run rh_cloud_insights:clean_statuses rake command
        8. Verify that host properties doesn't contain Red Hat Lightspeed status.

    :expectedresults:
        1. Host is successfully registered with capsule host,
            having remote execution and Red Hat Lightspeed enabled.
        2. Remote Execution job runs successfully on the host.
        3. rake command deletes Red Hat Lightspeed reporting status of host.

    :BZ: 2110222, 2112386, 1962930

    :parametrized: yes
    """
    org = rhcloud_manifest_org
    ak = rhcloud_activation_key
    # Enable rhel repos and install insights-client
    rhelver = rhel_contenthost.os_version.major
    rhel_contenthost.enable_ipv6_dnf_and_rhsm_proxy()
    if rhelver > 7:
        rhel_contenthost.create_custom_repos(**settings.repos[f'rhel{rhelver}_os'])
    else:
        rhel_contenthost.create_custom_repos(
            **{f'rhel{rhelver}_os': settings.repos[f'rhel{rhelver}_os']}
        )
    with module_target_sat_insights.ui_session() as session:
        session.organization.select(org_name=org.name)

        # Generate host registration command
        cmd = session.host_new.get_register_command(
            {
                'general.organization': org.name,
                'general.capsule': rhcloud_capsule.hostname,
                'general.activation_keys': ak.name,
                'general.insecure': True,
                'advanced.setup_insights': 'Yes (override)',
                'advanced.setup_rex': 'Yes (override)',
            }
        )
        # Register host with Satellite and Red Hat Lightspeed.
        rhel_contenthost.execute(cmd)
        assert rhel_contenthost.subscribed
        assert rhel_contenthost.execute('insights-client --test-connection').status == 0
        values = session.host_new.get_host_statuses(rhel_contenthost.hostname)
        assert values['Red Hat Lightspeed']['Status'] == 'Reporting'

        # Verify Remote Execution is functional by running a simple job
        template_id = (
            module_target_sat_insights.api.JobTemplate()
            .search(query={'search': 'name="Run Command - Ansible Default"'})[0]
            .id
        )
        job = module_target_sat_insights.api.JobInvocation().run(
            synchronous=False,
            data={
                'job_template_id': template_id,
                'targeting_type': 'static_query',
                'search_query': f'name = {rhel_contenthost.hostname}',
                'inputs': {'command': 'id'},
            },
        )
        module_target_sat_insights.wait_for_tasks(
            f'resource_type = JobInvocation and resource_id = {job["id"]}',
            poll_timeout=300,
        )
        job_result = module_target_sat_insights.api.JobInvocation(id=job['id']).read()
        assert job_result.succeeded == 1, 'Remote Execution job failed on the host'

        # Clean Red Hat Lightspeed status.
        result = module_target_sat_insights.run(
            f'foreman-rake rh_cloud_insights:clean_statuses SEARCH="{rhel_contenthost.hostname}"'
        )
        assert 'Deleted 1 insights statuses' in result.stdout
        assert result.status == 0
        # Workaround for not reading old data.
        session.browser.refresh()
        # Verify that status is cleared.
        values = session.host_new.get_host_statuses(rhel_contenthost.hostname)
        assert values['Red Hat Lightspeed']['Status'] == 'N/A'
        result = rhel_contenthost.run('insights-client')
        assert result.status == 0
        # Workaround for not reading old data.
        session.browser.refresh()
        # Verify status again.
        values = session.host_new.get_host_statuses(rhel_contenthost.hostname)
        assert values['Red Hat Lightspeed']['Status'] == 'Reporting'


@pytest.mark.no_containers
@pytest.mark.rhel_ver_list([settings.content_host.default_rhel_version])
def test_host_breadcrumb_switcher_updates_insights_tabs(
    rhel_insights_vms,
    rhcloud_manifest_org,
    module_target_sat_insights,
):
    """Test that breadcrumb switcher properly updates Recommendations tab
    when switching between hosts on the host details page.

    :id: e9f3fde8-c56b-42de-921f-576c83efcec7

    :steps:
        1. Prepare one host with recommendations (host1) and one without (host2).
        2. Upload data and sync recommendations.
        3. Navigate to host1's details page and verify Recommendations tab shows recommendations.
        4. Use breadcrumb switcher to switch to host2 (without full page navigation).
        5. Verify that Recommendations tab updates to show no recommendations for host2.
        6. Switch back to host1 and verify recommendations are displayed again.

    :expectedresults:
        1. Host1 displays recommendations in the Recommendations tab.
        2. After switching to host2 via breadcrumb, tab shows no recommendations.
        3. After switching back to host1 via breadcrumb, recommendations are displayed again.
        4. The tab content properly updates with each breadcrumb switch without requiring page reload.

    :parametrized: yes

    :Verifies: SAT-38703
    """
    org_name = rhcloud_manifest_org.name

    host1, host2 = rhel_insights_vms

    # Only create recommendations on host1, so that host1 and host2 have different data
    # This allows us to verify that the tab actually updates when switching hosts
    create_recommendation(host1)

    with module_target_sat_insights.ui_session() as session:
        session.organization.select(org_name=org_name)

        # Sync recommendations
        sync_recommendations(session, module_target_sat_insights)

        # Get baseline recommendations for host1
        recommendations_host1 = session.host_new.get_recommendations(host1.hostname)
        assert len(recommendations_host1) > 0, f"No recommendations found for {host1.hostname}"

        # Get baseline recommendations for host2
        recommendations_host2 = session.host_new.get_recommendations(host2.hostname)

        # Store recommendation counts and titles for comparison
        host1_titles = {rec['Recommendation'] for rec in recommendations_host1}
        host2_titles = {rec['Recommendation'] for rec in recommendations_host2}

        # Verify that host1 has not same recommendations as host2
        assert set(host1_titles) != set(host2_titles), (
            "Host1 and Host2 should not have same recommendations"
        )

        # Navigate back to host1's details page
        session.host_new.get_recommendations(host1.hostname)

        # Use breadcrumb switcher to switch to host2
        session.host_new.select_host_from_breadcrumb(host2.hostname)

        # Read the Recommendations tab content after breadcrumb switch
        recommendations_after_switch = session.host_new.read_current_recommendations_tab()

        titles_after_switch = {rec['Recommendation'] for rec in recommendations_after_switch}

        assert titles_after_switch == host2_titles, (
            f"After breadcrumb switch to host2, expected host2 data. "
            f"Expected: {host2_titles}, Got: {titles_after_switch}"
        )

        # Verify we're NOT showing host1's recommendations (the bug scenario)
        assert titles_after_switch != host1_titles, (
            f"BUG: Breadcrumb switcher did not update Recommendations tab. "
            f"Still showing {len(recommendations_after_switch)} recommendations from host1 "
            f"instead of host2's recommendations list."
        )

        # Switch back to host1 using breadcrumb
        session.host_new.select_host_from_breadcrumb(host1.hostname)

        # Verify the tab updates to show host1's recommendations again (not empty)
        recommendations_back = session.host_new.read_current_recommendations_tab()

        # Verify we see host1's recommendations again
        assert len(recommendations_back) > 0, (
            f"After switching back to host1, expected to see recommendations again, "
            f"but got {len(recommendations_back)} recommendations"
        )

        titles_back_to_host1 = {rec['Recommendation'] for rec in recommendations_back}
        assert titles_back_to_host1 == host1_titles, (
            f"After switching back to host1 via breadcrumb, expected host1 recommendations. "
            f"Expected: {host1_titles}, Got: {titles_back_to_host1}"
        )
