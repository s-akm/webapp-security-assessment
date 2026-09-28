class Catalog {
    Node find(XPath xp, Document doc, String sku) throws Exception {
        return (Node) xp.evaluate(String.format("//item[@sku='%s']", sku), doc, XPathConstants.NODE);
    }
}
