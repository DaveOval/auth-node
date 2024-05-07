import { Router } from 'express';
import { AuthMiddleware } from '../middlewares/auth.middleware';
import { FileUploadController } from './controller';
import { FileUploadService } from '../services/file-upload.service';
import { FileUploadMiddleware } from '../middlewares/file-upload.middleware';
import { TypeMiddleware } from '../middlewares/type.middleware';


export class FileUploadRoutes {

  static get routes(): Router {

    const router = Router();
    const controller = new FileUploadController(
      new FileUploadService()
    );
    
    router.use( FileUploadMiddleware.containeFiles );
    //router.use( TypeMiddleware.validTypes(["users" , "products" , "categories"]) );

    // Definir las rutas
    router.post( '/single/:type', controller.uploadFile );
    router.post( '/multiple/:type', controller.uploadMultipleFiles );

    return router;
  }


}

