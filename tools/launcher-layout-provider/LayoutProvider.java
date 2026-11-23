package org.a22x.workspace;

import android.content.ContentProvider;
import android.content.ContentValues;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.content.pm.ResolveInfo;
import android.content.res.AssetFileDescriptor;
import android.database.Cursor;
import android.net.Uri;
import android.os.Binder;
import java.io.FileNotFoundException;
import java.io.IOException;

public final class LayoutProvider extends ContentProvider {
    @Override public boolean onCreate() { return true; }
    @Override public String getType(Uri uri) { return "application/xml"; }

    @Override public AssetFileDescriptor openAssetFile(Uri uri, String mode) throws FileNotFoundException {
        if (!"r".equals(mode) || !"/launcher_layout".equals(uri.getPath())) {
            throw new FileNotFoundException("Unknown layout request");
        }
        int caller = Binder.getCallingUid();
        Intent homeIntent = new Intent(Intent.ACTION_MAIN).addCategory(Intent.CATEGORY_HOME);
        PackageManager pm = getContext().getPackageManager();
        long token = Binder.clearCallingIdentity();
        try {
            ResolveInfo home = pm.resolveActivity(homeIntent, PackageManager.MATCH_DEFAULT_ONLY);
            if (home == null || home.activityInfo == null || home.activityInfo.applicationInfo.uid != caller) {
                throw new SecurityException("Only the selected home application may read this layout");
            }
            return getContext().getAssets().openFd("workspace.xml");
        } catch (IOException ex) {
            throw new FileNotFoundException(ex.getMessage());
        } finally {
            Binder.restoreCallingIdentity(token);
        }
    }

    @Override public Cursor query(Uri uri, String[] projection, String selection,
                                  String[] args, String order) { throw new UnsupportedOperationException(); }
    @Override public Uri insert(Uri uri, ContentValues value) { throw new UnsupportedOperationException(); }
    @Override public int update(Uri uri, ContentValues value, String where, String[] args) { throw new UnsupportedOperationException(); }
    @Override public int delete(Uri uri, String where, String[] args) { throw new UnsupportedOperationException(); }
}
