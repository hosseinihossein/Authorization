import { ApplicationConfig, ErrorHandler, provideBrowserGlobalErrorListeners } from '@angular/core';
import { provideRouter } from '@angular/router';

import { routes } from './app.routes';
import { MyErrorHandler } from './shared/my-error-handler';

export const appConfig: ApplicationConfig = {
  providers: [
    //provideBrowserGlobalErrorListeners(),
    {provide: ErrorHandler, useClass: MyErrorHandler},
    provideRouter(routes),
  ]
};
