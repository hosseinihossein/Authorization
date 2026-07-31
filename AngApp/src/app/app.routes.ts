import { Routes } from '@angular/router';
import { Consent } from './consent/consent';
import { Authorizing } from './authorizing/authorizing';

export const routes: Routes = [
    {path: "Authorize/Consent", component: Consent},
    {path: "Account/Login", redirectTo: (activatedRouteSnapshot)=>{
            window.location.href = 
            `https://localhost:5444/?ReturnUrl=https://localhost:5443/${activatedRouteSnapshot.queryParamMap.get("ReturnUrl")}`;
            return "";
        }
    },
    {path: "", component: Authorizing},
];
