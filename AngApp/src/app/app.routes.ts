import { Routes } from '@angular/router';
import { Consent } from './consent/consent';
import { Authorizing } from './authorizing/authorizing';

export const routes: Routes = [
    {path: "Authorize/Consent", component: Consent},
    {path: "Account/Login", redirectTo: ()=>{
            window.location.href = "https://localhost:5444";
            return "";
        }
    },
    {path: "", component: Authorizing},
];
