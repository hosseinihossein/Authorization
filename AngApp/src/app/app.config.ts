import { ApplicationConfig, ErrorHandler, provideBrowserGlobalErrorListeners } from '@angular/core';
import { provideRouter } from '@angular/router';

import { routes } from './app.routes';
import { MyErrorHandler } from './shared/my-error-handler';

import { provideAuth, LogLevel } from 'angular-auth-oidc-client';

export const appConfig: ApplicationConfig = {
  providers: [
    //provideBrowserGlobalErrorListeners(),
    {provide: ErrorHandler, useClass: MyErrorHandler},
    provideRouter(routes),
    provideAuth({
      config: {
        authority: 'https://localhost:5443',
        redirectUrl: "https://localhost:5443",
        postLogoutRedirectUri: "https://localhost:5443",
        clientId: 'AngAuthorizationApp001',
        scope: 'openid email roles offline_access',
        responseType: 'code',
        silentRenew: true,
        useRefreshToken: true,
        logLevel: LogLevel.Debug,
      },
    }),
  ]
};
