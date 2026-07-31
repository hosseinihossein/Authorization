import { Routes } from '@angular/router';
import { Consent } from './consent/consent';
import { Authorizing } from './authorizing/authorizing';

export const routes: Routes = [
    {path: "Authorize/Consent", component: Consent},
    {path: "", component: Authorizing},
];
