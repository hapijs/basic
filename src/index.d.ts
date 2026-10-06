import type { Plugin, Request, ResponseToolkit } from '@hapi/hapi';

export interface ValidateCustomResponse {
    response: any;
}

export interface ValidateResponse {
    isValid: boolean;
    credentials?: any;
}

export interface Validate {
    (
        request: Request,
        username: string,
        password: string,
        h: ResponseToolkit,
    ): Promise<ValidateResponse | ValidateCustomResponse>;
}

export declare const plugin: Plugin<{}>;
