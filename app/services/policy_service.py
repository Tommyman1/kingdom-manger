class PolicyService:
    def interruption_decision(self, *, activity: dict, classification: dict):
        if classification['update_policy'] in {'manual', 'stack-controlled'}:
            return {
                'safe': False,
                'decision': 'LOCKED',
                'reason': classification['update_policy'].replace('-', ' '),
            }
        if activity.get('safe_to_interrupt'):
            return {'safe': True, 'decision': 'SAFE', 'reason': activity.get('reason')}
        return {'safe': False, 'decision': 'WAIT', 'reason': activity.get('reason')}

    def update_decision(self, *, activity: dict, classification: dict, security_incident: bool = False, update_available: bool = False):
        interruption = self.interruption_decision(activity=activity, classification=classification)
        reasons = []
        if not update_available:
            reasons.append('no update available')
        if security_incident:
            reasons.append('active security incident')
        if not interruption['safe']:
            reasons.append(interruption['reason'])
        allowed = update_available and not security_incident and interruption['safe']
        return {'allowed': allowed, 'reasons': reasons, 'interruption': interruption}
