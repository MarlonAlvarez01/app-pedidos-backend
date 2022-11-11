import { AuthenticationStrategy } from '@loopback/authentication';
import {Request, RedirectRoute, HttpErrors} from '@loopback/rest';
import {UserProfile} from '@loopback/security';
import {ParamsDictionary} from 'express-serve-static-core';
import {ParsedQs} from 'qs';
import parseBearerToken from 'parse-bearer-token';
import {service} from '@loopback/core';
import {AutenticacionService} from '../services';
export class EstrategiaAdministrador implements AuthenticationStrategy{
  name: string = 'admin';

  constructor(
    @service(AutenticacionService)
    public serviceAutenticacion: AutenticacionService
  ){

  }

  async authenticate(request: Request): Promise<UserProfile | RedirectRoute | undefined> {
    let token = parseBearerToken(request);
    if (token){
      let datos = this.serviceAutenticacion.ValidarTokenJWT(token);
      if (datos){
        let perfil: UserProfile = Object.assign({
          nombre: datos.data.nombre
        });
        return perfil;
      }else{
        throw new HttpErrors[401]("El token incluido no es valido")
      }
    }else{
      throw new HttpErrors[401]("No se ha iniciado un token en la solicitud")
    }


  }
}
