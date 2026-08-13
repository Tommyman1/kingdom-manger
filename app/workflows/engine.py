class WorkflowEngine:
    """Home for workflows migrated from n8n.

    Initial release is deliberately inert. Existing n8n workflows stay live
    until each workflow is implemented and verified here.
    """

    def list_workflows(self):
        return [
            {'name': 'media-security-pipeline', 'status': 'n8n-active', 'kingdom_manager': 'planned'},
            {'name': 'weekly-report', 'status': 'n8n-active', 'kingdom_manager': 'optional-later'},
        ]
