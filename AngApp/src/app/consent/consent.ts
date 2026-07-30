import { Component, inject } from '@angular/core';
import { ActivatedRoute } from '@angular/router';

@Component({
  selector: 'app-consent',
  imports: [],
  templateUrl: './consent.html',
  styleUrl: './consent.css',
})
export class Consent {
  activatedRoute = inject(ActivatedRoute);
}
