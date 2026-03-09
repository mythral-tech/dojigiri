package com.example.xxe;

import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;
import org.xml.sax.helpers.DefaultHandler;

import javax.xml.parsers.SAXParser;

@RestController
@RequestMapping("/api/import")
public class ImportHandler {

    @PostMapping("/xml")
    public String importXml(@RequestParam("file") MultipartFile file)
            throws Exception {
        SAXParser parser = XmlParserFactory.createParser();
        DataHandler handler = new DataHandler();
        parser.parse(file.getInputStream(), handler);
        return "Imported " + handler.getRecordCount() + " records";
    }

    private static class DataHandler extends DefaultHandler {
        private int recordCount = 0;

        @Override
        public void endElement(String uri, String localName, String qName) {
            if ("record".equals(qName)) {
                recordCount++;
            }
        }

        public int getRecordCount() {
            return recordCount;
        }
    }
}
