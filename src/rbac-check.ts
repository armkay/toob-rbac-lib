import { RbacDal } from "./rbac-dal";
import { ForbiddenError, UnauthorizedError } from "./errors";

export async function ensurePermission(
    event: any,
    tenantId: string,
    requiredPermission: string
) {
    const dal = new RbacDal();

    const sub = event.requestContext?.authorizer?.lambda?.sub;
    if (!sub) {
        throw new UnauthorizedError("Missing Cognito sub");
    }

    const roles = await dal.getUserRoles(tenantId, sub);
    if (!roles || roles.length === 0) {
        throw new ForbiddenError("User has no assigned roles");
    }

    const permissionSet = new Set<string>();

    for (const role of roles) {
        const perms = await dal.getPermissionsForRole(tenantId, role);

        if (Array.isArray(perms)) {
            for (const p of perms) permissionSet.add(p);
        }
    }

    if (!permissionSet.has(requiredPermission)) {
        throw new ForbiddenError(
            `Missing permission: ${requiredPermission} (user roles: ${roles.join(", ")})`
        );
    }

    return {
        roles,
        permissions: Array.from(permissionSet)
    };
}
