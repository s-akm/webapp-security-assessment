<?php
class DocumentController {
    private $forbiddenMimeTypes = ['application/x-httpd-php'];
    public function store($request) {
        $doc = $request->file('doc');
        if (in_array($doc->getClientMimeType(), $this->forbiddenMimeTypes)) { abort(415); }
    }
}
