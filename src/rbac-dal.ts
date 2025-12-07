import { DeleteItemCommand, DynamoDBClient, GetItemCommand, PutItemCommand, QueryCommand, UpdateItemCommand } from "@aws-sdk/client-dynamodb";
import { unmarshall } from "@aws-sdk/util-dynamodb";

export class RbacDal {
    private client: DynamoDBClient;
    constructor() {
        this.client = new DynamoDBClient({ region: "ca-central-1" });
    }

    public getUserRole(tenantId: string, sub: string): Promise<string | null> {
        return new Promise<string | null>(async (resolve, reject) => {
            try {
                const command = new GetItemCommand({
                    TableName: "role_access_policy",
                    Key: {
                        PK: { S: `TENANT#${tenantId}` },
                        SK: { S: `USER#${sub}` }
                    }
                });

                const response = await this.client.send(command);
                if (!response.Item) return null;

                const item = unmarshall(response.Item);
                resolve(item.role ?? null);
            } catch (e) {
                console.error(e);
                reject(e);
            }
        });
    }

    public async getPermissionsForRole(tenantId: string, role: string): Promise<string[]> {
        const command = new GetItemCommand({
            TableName: "role_access_policy",
            Key: {
                PK: { S: `TENANT#${tenantId}` },
                SK: { S: `ROLE#${role}` }
            }
        });

        const response = await this.client.send(command);
        console.log(`response : ${JSON.stringify(response)}`)
        if (!response.Item) return [];

        const item = unmarshall(response.Item);
        return item.permissions || [];
    }

    public async setRoleAccess(tenantId: string, sub: string, role: string): Promise<void> {
        const command = new PutItemCommand({
            TableName: "role_access_policy",
            Item: {
                PK: { S: `TENANT#${tenantId}` },
                SK: { S: `USER#${sub}` },
                role: { S: role }
            }
        });

        await this.client.send(command);
    }

    public async deleteUserRole(tenantId: string, user: string): Promise<void> {
        const command = new DeleteItemCommand({
            TableName: "role_access_policy",
            Key: {
                PK: { S: `TENANT#${tenantId}` },
                SK: { S: `USER#${user}` }
            }
        });

        await this.client.send(command);
    }

    public async getAllRolePermissions(tenantId: string): Promise<any> {
        const command = new QueryCommand({
            TableName: 'role_access_policy',
            KeyConditionExpression: 'PK = :pk AND begins_with(SK, :sk)',
            ExpressionAttributeValues: {
                ':pk': { S: `TENANT#${tenantId}` },
                ':sk': { S: 'ROLE#' }
            }
        });

        const result = await this.client.send(command);

        const roles = (result.Items || []).map(item => {
            const unmarshalled = unmarshall(item);
            return {
                role: unmarshalled.SK.replace('ROLE#', ''),
                permissions: unmarshalled.permissions
            };
        });

        return roles;
    }

    public async createRole(tenantId: string, role: string, permissions: string[]): Promise<void> {
        const command = new PutItemCommand({
            TableName: "role_access_policy",
            Item: {
                PK: { S: `TENANT#${tenantId}` },
                SK: { S: `ROLE#${role}` },
                permissions: { L: permissions.map(p => ({ S: p })) }
            }
        });

        await this.client.send(command);
    }

    public async updateRolePermissions(tenantId: string, role: string, permissions: string[]): Promise<void> {
        const command = new PutItemCommand({
            TableName: "role_access_policy",
            Item: {
                PK: { S: `TENANT#${tenantId}` },
                SK: { S: `ROLE#${role}` },
                permissions: { L: permissions.map(p => ({ S: p })) }
            }
        });

        await this.client.send(command);
    }

    public async listUserRoles(tenantId: string): Promise<any[]> {
        const command = new QueryCommand({
            TableName: "role_access_policy",
            KeyConditionExpression: "PK = :pk AND begins_with(SK, :sk)",
            ExpressionAttributeValues: {
                ":pk": { S: `TENANT#${tenantId}` },
                ":sk": { S: "USER#" }
            }
        });

        const result = await this.client.send(command);

        const map: Record<string, string[]> = {};

        for (const item of result.Items || []) {
            const unmarshalled = unmarshall(item);
            const sk = unmarshalled.SK;

            const [, sub, , role] = sk.split("#");

            if (!map[sub]) map[sub] = [];
            map[sub].push(role);
        }

        return Object.entries(map).map(([user, roles]) => ({ user, roles }));
    }


    async addPermissionToRole(
        tenantId: string,
        role: string,
        permissionArray: string[]
    ) {
        if (!Array.isArray(permissionArray)) {
            throw new Error("permission_array must be an array");
        }

        const marshalledList = {
            L: permissionArray.map(p => ({ S: p }))
        };

        const command = new UpdateItemCommand({
            TableName: "role_access_policy",
            Key: {
                PK: { S: `TENANT#${tenantId}` },
                SK: { S: `ROLE#${role}` }
            },
            UpdateExpression: "SET #p = list_append(if_not_exists(#p, :empty), :new)",
            ExpressionAttributeNames: {
                "#p": "permissions"
            },
            ExpressionAttributeValues: {
                ":empty": { L: [] },
                ":new": marshalledList
            }
        });

        return this.client.send(command);
    }


    public async removePermissionFromRole(
        tenantId: string,
        role: string,
        removePermissions: string[]
    ): Promise<void> {
        const currentPermissions = await this.getPermissionsForRole(tenantId, role);

        const updatedPermissions = currentPermissions.filter(
            (p) => !removePermissions.includes(p)
        );

        const command = new UpdateItemCommand({
            TableName: "role_access_policy",
            Key: {
                PK: { S: `TENANT#${tenantId}` },
                SK: { S: `ROLE#${role}` }
            },
            UpdateExpression: "SET permissions = :p",
            ExpressionAttributeValues: {
                ":p": { L: updatedPermissions.map((p) => ({ S: p })) }
            }
        });

        await this.client.send(command);
    }

    public async assignUserRole(tenantId: string, sub: string, role: string): Promise<void> {
        const command = new PutItemCommand({
            TableName: "role_access_policy",
            Item: {
                PK: { S: `TENANT#${tenantId}` },
                SK: { S: `USER#${sub}#ROLE#${role}` }
            }
        });

        await this.client.send(command);
    }

    public async getUserRoles(tenantId: string, sub: string): Promise<string[]> {
        const command = new QueryCommand({
            TableName: "role_access_policy",
            KeyConditionExpression: "PK = :pk AND begins_with(SK, :sk)",
            ExpressionAttributeValues: {
                ":pk": { S: `TENANT#${tenantId}` },
                ":sk": { S: `USER#${sub}#ROLE#` }
            }
        });

        const result = await this.client.send(command);

        return (result.Items || []).map(item => {
            const sk = unmarshall(item).SK;
            return sk.split("#ROLE#")[1];
        });
    }




}
