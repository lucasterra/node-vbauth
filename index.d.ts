import { Connection, PoolConnection, PoolConfig } from "@types/mysql";
import { RequestHandler, Request, Response } from "@types/express";
import { RedisClient } from "@types/redis";

interface VBSessionInfo {
  userid: number;
  username: string;
  usergroupid: number;
  membergroupids: Array<string>;
  email: string;
  posts: number;
  subscriptionexpirydate: number;
  subscriptionstatus: number;
}

interface VBAuthOptions {
  cookieSalt: string;
  cookiePrefix?: string;
  cookieTimeout?: number;
  cookieDomain?: string;
  defaultPath?: string | null;
  useStrikeSystem?: boolean;
  refreshActivity?: boolean;
  secureCookies?: boolean;
  subscriptions?: boolean;
  subscriptionId?: number;
  sessionIpOctetLength?: number;
  redisCache?: RedisClient;
  isUser?: (user: VBUserInfo) => boolean;
  isAdmin?: (user: VBUserInfo) => boolean;
  isModerator?: (user: VBUserInfo) => boolean;
}

type UserTypes = "admin" | "moderator" | "user";
type LoginResponses =
  | "success"
  | "failed, login and password are required"
  | "failed, too many tries"
  | "failed, wrong login or password";

declare class VBAuth {
  constructor(
    database: Connection | PoolConnection | PoolConfig,
    options: VBAuthOptions
  );

  session: () => RequestHandler;
  mustBeUser: () => RequestHandler;
  mustBeModerator: () => RequestHandler;
  mustBeAdmin: () => RequestHandler;
  login: (
    username: string,
    password: string,
    rememberme: boolean,
    loginType: UserTypes,
    req: Request,
    res: Response
  ) => Promise<LoginResponses>;
  logout: RequestHandler;
}

declare global {
  export namespace Express {
    export interface Request {
       vbuser: VBSessionInfo;
    }
  }
}

export = VBAuth;
