package com.xebyte.offline;

import com.xebyte.core.ServiceUtils;
import junit.framework.TestCase;

/** Offline tests for {@link ServiceUtils#stripTypeQualifiers(String)}. */
public class ServiceUtilsTypeQualifiersTest extends TestCase {

    public void testLeadingConst() {
        assertEquals("char *", ServiceUtils.stripTypeQualifiers("const char *"));
    }

    public void testTrailingConstOnType() {
        assertEquals("char *", ServiceUtils.stripTypeQualifiers("char const *"));
    }

    public void testConstPointer() {
        assertEquals("char *", ServiceUtils.stripTypeQualifiers("char * const"));
        assertEquals("char * *", ServiceUtils.stripTypeQualifiers("const char * const *"));
    }

    public void testVolatile() {
        assertEquals("int *", ServiceUtils.stripTypeQualifiers("volatile int *"));
        assertEquals("unsigned int", ServiceUtils.stripTypeQualifiers("const volatile unsigned int"));
    }

    public void testPrototypeKeepsEverythingElse() {
        assertEquals("void __fastcall ExecuteStarChatCommand(char *commandText)",
                ServiceUtils.stripTypeQualifiers(
                        "void __fastcall ExecuteStarChatCommand(const char *commandText)"));
        assertEquals("int Foo(char *a, int b, Bar * c)",
                ServiceUtils.stripTypeQualifiers("int Foo(const char *a, const int b, const Bar * const c)"));
    }

    public void testNoSpaceLeftBeforeClosingParen() {
        assertEquals("void f(char *)", ServiceUtils.stripTypeQualifiers("void f(const char *)"));
    }

    public void testMatchesWholeWordsOnly() {
        for (String s : new String[] {
                "const_value", "constant", "Constructor", "myconst", "volatile_t", "$const", "int const_x"}) {
            assertSame(s, s, ServiceUtils.stripTypeQualifiers(s));
        }
        assertEquals("int const_x", ServiceUtils.stripTypeQualifiers("const int const_x"));
    }

    public void testUnqualifiedTextIsReturnedUnchanged() {
        String s = "unsigned  int   *";
        assertSame(s, ServiceUtils.stripTypeQualifiers(s));
    }

    public void testNullAndEmpty() {
        assertNull(ServiceUtils.stripTypeQualifiers(null));
        assertEquals("", ServiceUtils.stripTypeQualifiers(""));
        assertEquals("", ServiceUtils.stripTypeQualifiers("const"));
    }
}
