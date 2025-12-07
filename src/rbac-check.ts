import { RbacDal } from "./rbac-dal";
import { ForbiddenError, UnauthorizedError } from "./errors";

export async function ensurePermission(
    event: any,
    tenantId: string,
    requiredPermission: string
) {
    const dal = new RbacDal();

    const sub = event.requestContext?.authorizer?.lambda?.sub;
    if (!sub) throw new UnauthorizedError("Missing Cognito sub");

    const role = await dal.getUserRole(tenantId, sub);
    if (!role) throw new ForbiddenError("User has no assigned role");

    const permissions = await dal.getPermissionsForRole(tenantId, role);

    if (!permissions.includes(requiredPermission)) {
        throw new ForbiddenError(`Missing permission: ${requiredPermission}`);
    }

    return { role, permissions };
}
