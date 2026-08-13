class PolicyService:
    def update_decision(self, *, activity: dict, security_incident: bool = False, update_available: bool = False):
        reasons = []
        if not update_available:
            reasons.append('no update available')
        if security_incident:
            reasons.append('active security incident')
        if not activity.get('safe_to_interrupt', False):
            reasons.append(activity.get('reason', 'not safe to interrupt'))
        allowed = update_available and not security_incident and activity.get('safe_to_interrupt', False)
        return {'allowed': allowed, 'reasons': reasons}
