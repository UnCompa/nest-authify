export interface CanActivate {
    canActivate(context: any): Promise<boolean> | boolean;
}
export declare abstract class JwtAuthGuard implements CanActivate {
    abstract canActivate(context: any): Promise<boolean>;
}
