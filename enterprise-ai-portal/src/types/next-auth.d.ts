import { DefaultSession } from 'next-auth';

declare module 'next-auth' {
  interface Session {
    user: {
      id: string;
      department: string | null;
      departmentId: string | null;
      departmentVersion?: number;
      chatAllowed: boolean;
      portalAllowed?:boolean;
      tenantId?:string;
      role: string;
      externalSubject?: string | null;
      localLogin?: boolean;
      localCredentialVersion?: number;
    } & DefaultSession['user'];
  }
}

declare module 'next-auth/jwt' {
  interface JWT {
    department?: string | null;
    departmentId?: string | null;
    departmentVersion?: number;
    chatAllowed?: boolean;
      portalAllowed?: boolean;
      tenantId?: string;
    controlPlaneUserId?: string;
    role?: string;
    externalSubject?: string;
    localLogin?: boolean;
    localCredentialVersion?: number;
  }
}
