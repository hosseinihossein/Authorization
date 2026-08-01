import { Routes } from '@angular/router';
import { Consent } from './consent/consent';
import { WaitSpinner } from './shared/wait-spinner/wait-spinner';

export const routes: Routes = [
    {path: "Authorize/Consent", component: Consent},
    {path: "Account/Login", redirectTo: (activatedRouteSnapshot)=>{
            let url = new URL("https://localhost:5444/");
            for(let key of activatedRouteSnapshot.queryParamMap.keys){
                url.searchParams.append(key, activatedRouteSnapshot.queryParamMap.get(key)!);
            }
            window.location.href = url.toString();
            return "";
        }
    },
    {path: "", component: WaitSpinner},
];
