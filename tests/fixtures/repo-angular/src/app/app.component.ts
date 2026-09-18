@Component({ selector: 'app-root', template: '<div [innerHTML]="html"></div>' })
export class AppComponent {
  html = this.sanitizer.bypassSecurityTrustHtml(this.raw);
}
