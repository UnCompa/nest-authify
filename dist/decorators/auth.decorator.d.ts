export declare const IS_PUBLIC_KEY = "isPublic";
export declare const ROLES_KEY = "roles";
export declare function Auth(options?: {
    isPublic?: boolean;
    roles?: string[];
}): <TFunction extends Function, Y>(target: TFunction | object, propertyKey?: string | symbol, descriptor?: TypedPropertyDescriptor<Y>) => void;
//# sourceMappingURL=auth.decorator.d.ts.map