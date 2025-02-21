import { Injectable } from '@angular/core';
import { HttpInterceptor, HttpRequest, HttpHandler, HttpEvent, HttpErrorResponse } from '@angular/common/http';
import { Observable, throwError } from 'rxjs';
import { HttpServiceService } from './http-service.service';
import { Router } from '@angular/router';
import { catchError } from 'rxjs/operators';



@Injectable({
  providedIn: 'root'
})
export class AuthService implements HttpInterceptor {
  token : any

  constructor(private router : Router) { }
  
  intercept(req: HttpRequest<any>, next: HttpHandler):Observable<HttpEvent<any>> {
    console.log('in auth service intercept method....!!!')


    if (localStorage.getItem('fname') && localStorage.getItem('token')) {
   this.token =    localStorage.getItem('token')
      // To modify an HttpRequest ,clone()
      req = req.clone({
        setHeaders: {
        "withCredentials" : "true",
        "name" : "rohit",
          
          Authorization: this.token
        }
      })
    }

    //interceptors transform the outgoing request before passing it to the next 
        //interceptor in the chain, by calling next.handle()
  
        console.log(req.headers.get("Authorization"))
        return next.handle(req).pipe(
          catchError((error: HttpErrorResponse) => {
            if (error.status === 401) {
              localStorage.clear();
              this.router.navigate(['/login'], {
                queryParams: { errorMessage: error.error },
              });
            }
            if (error.status === 403) {
              localStorage.clear();
              this.router.navigate(['/login'], {
                queryParams: { errorMessage: 'Token is expired... plz login again..!rrr!  ' },
              });
            }
            return throwError(error);
          })
        );
         }


  }






