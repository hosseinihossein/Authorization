import { Component } from '@angular/core';
import { WaitSpinner } from '../shared/wait-spinner/wait-spinner';

@Component({
  selector: 'app-authorizing',
  imports: [WaitSpinner,],
  templateUrl: './authorizing.html',
  styleUrl: './authorizing.css',
})
export class Authorizing {}
