package org.gwtproject;

import org.gwtproject.client.CatalogGWTTest;
import com.google.gwt.junit.tools.GWTTestSuite;
import junit.framework.Test;
import junit.framework.TestSuite;

public class CatalogGWTSuite extends GWTTestSuite {
  public static Test suite() {
    TestSuite suite = new TestSuite("Tests for CatalogGWT");
    suite.addTestSuite(CatalogGWTTest.class);
    return suite;
  }
}
