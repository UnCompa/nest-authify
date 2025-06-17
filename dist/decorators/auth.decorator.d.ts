export declare function Auth(options?: {
    isPublic?: boolean;
    roles?: string[];
}): <TFunction extends Function, Y>(target: object | TFunction, propertyKey?: string | symbol, descriptor?: TypedPropertyDescriptor<Y>) => void;
