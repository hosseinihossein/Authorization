import { Routes } from '@angular/router';
import { Consent } from './consent/consent';
import { Authorizing } from './authorizing/authorizing';

export const routes: Routes = [
    {path: "Authorize/Consent", component: Consent},
    {path: "Account/Login", redirectTo: (activatedRouteSnapshot)=>{
            let url = new URL("https://localhost:5444/");
            for(let key of activatedRouteSnapshot.queryParamMap.keys){
                if(key === "ReturnUrl"){
                    url.searchParams.append(key, "https://localhost:5443/"+activatedRouteSnapshot.queryParamMap.get(key)!);
                }
                url.searchParams.append(key, activatedRouteSnapshot.queryParamMap.get(key)!);
            }
            window.location.href = url.toString();
            //`https://localhost:5444/?ReturnUrl=https://localhost:5443/${activatedRouteSnapshot.queryParamMap.get("ReturnUrl")}`;
            return "";
        }
    },
    /*{path: "Authorization/Api/Authorize", redirectTo: (activatedRouteSnapshot)=>{
            if(activatedRouteSnapshot.queryParamMap.has("redirect_uri")){
                let url = new URL(activatedRouteSnapshot.queryParamMap.get("redirect_uri")! + "/");
                for(let key of activatedRouteSnapshot.queryParamMap.keys){
                    url.searchParams.append(key, activatedRouteSnapshot.queryParamMap.get(key)!);
                }
                console.log(url.toString());
                //window.location.href = url.toString();
            }
            return "";
        }
    },*/
    {path: "", component: Authorizing},
];
