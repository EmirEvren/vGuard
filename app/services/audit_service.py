from app.models.audit import AuditLog
from app.extensions import db
from sqlalchemy import func

def get_audit_logs(limit=300, action=None, actor=None):
    query = AuditLog.query
    
    if action:
        query = query.filter(AuditLog.action == action)
    if actor:
        query = query.filter(AuditLog.actor == actor)
        
    query = query.order_by(AuditLog.timestamp.desc())
    
    if limit:
        query = query.limit(limit)
        
    return [log.to_dict() for log in query.all()]

def get_audit_stats():
    stats = {
        'total': AuditLog.query.count(),
        'by_action': {},
        'by_actor': {}
    }
    
    for action, count in db.session.query(AuditLog.action, func.count(AuditLog.id)).group_by(AuditLog.action).all():
        stats['by_action'][action] = count
        
    for actor, count in db.session.query(AuditLog.actor, func.count(AuditLog.id)).group_by(AuditLog.actor).all():
        stats['by_actor'][actor] = count
        
    return stats
